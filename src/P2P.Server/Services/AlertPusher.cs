using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using P2P.Server.Data;

namespace P2P.Server.Services;

/// <summary>
/// 安全事件告警通道（M5-07/SEC-71、FR-S-826、07 §13.1、OQ-21③）：后台 HostedService 30s tick
/// 聚合判定 → HTTP POST 通用 JSON（schema p2p.alert/v1——暂无接收端不做厂商适配，ext 扩展位）。
/// 三类触发源：login_fail_burst（LoginThrottle IP 维四入口聚合）/ register_burst（register+
/// register_recover 钩子 RegistrationMetrics）/ stun_drop_burst（StunGuard 三分桶累计的窗口增量）。
/// 每 tick 现读 alert_* 七键（PUT 后 ≤30s 生效，不占 RestartKeys）；每类型静默窗内不重复推送
/// （阈值持续满足也静默）；推送失败下轮重试 ≤3 轮后丢弃+Serilog 日志（不入审计——高频非管理动作），
/// 全程在 HostedService 后台线程不触业务路径。窗口计数皆内存环形（告警基线随重启重置，与 §11 同口径）。
/// M5-08 起本 tick 兼载自动封禁判定（07 §13.3）：与 alert_enabled 开关独立——LoginThrottle IP 维
/// 快照（autoban_window_sec 窗）count ≥ autoban_fail_count → BlacklistStore.AddAuto（新入列才落
/// ip_auto_block 审计；autoban_enabled=0 只关判定，既有条目不受影响）。
/// </summary>
public sealed class AlertPusher(
    IDbContextFactory<AppDbContext> dbFactory,
    LoginThrottle loginThrottle,
    RegistrationMetrics registrationMetrics,
    TimeProvider? time = null,
    StunService? stun = null,
    BlacklistStore? blacklist = null,
    HttpClient? http = null,
    ILogger<AlertPusher>? logger = null,
    AuditLogger? audit = null) : BackgroundService
{
    public const string Schema = "p2p.alert/v1";
    public const string TypeLoginFailBurst = "login_fail_burst";
    public const string TypeRegisterBurst = "register_burst";
    public const string TypeStunDropBurst = "stun_drop_burst";
    public const string TypeTest = "test";

    private static readonly TimeSpan TickInterval = TimeSpan.FromSeconds(30);
    private const int MaxAttempts = 3;

    private readonly TimeProvider _time = time ?? TimeProvider.System;
    private readonly HttpClient _http = http ?? new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
    private readonly ILogger? _log = logger;
    private readonly Lock _gate = new();
    private readonly Dictionary<string, DateTime> _lastAlertAt = [];   // type → 上次实际推送时刻（静默窗）
    private readonly List<PendingAlert> _pending = [];                  // 待发送/重试队列
    private readonly Queue<(long Ticks, long Delta)> _stunDeltas = []; // 每 tick STUN 丢弃增量样本
    private long _lastStunTotal = -1; // -1=首个样本只建基线不计增量

    /// <summary>HostedService 主循环：30s tick（异常不退出——单轮失败仅丢本轮，下轮重评）。</summary>
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TickInterval, _time);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
                await TickSafeAsync(stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { /* 停机 */ }
    }

    /// <summary>单轮聚合判定+推送派发（internal 供测试直调；异常自吞不外泄）。</summary>
    internal async Task TickOnceAsync(CancellationToken ct = default)
    {
        // STUN 增量采样先于开关判定（连续性：关闭期间丢包计入恢复后首个窗口，基线不漂）
        SampleStun();
        // 自动封禁判定独立于告警开关（07 §13.3：autoban_enabled 只关判定，与本通道 alert_enabled 无关）
        await EvaluateAutobanAsync(ct).ConfigureAwait(false);

        var cfg = await ReadConfigAsync(ct);
        if (!cfg.Enabled || cfg.Url.Length == 0) return;

        var now = _time.GetLocalNow().UtcDateTime;
        var login = loginThrottle.SnapshotIpWindow(cfg.WindowSec);
        TryEnqueue(TypeLoginFailBurst, login.Sum(s => s.Count), cfg.LoginFailCount, cfg.WindowSec,
            now, cfg.SilenceSec, login);
        var register = registrationMetrics.SnapshotIpWindow(cfg.WindowSec);
        TryEnqueue(TypeRegisterBurst, register.Sum(s => s.Count), cfg.RegisterCount, cfg.WindowSec,
            now, cfg.SilenceSec, register);
        // STUN 丢弃无源维度（StunGuard 全局计数）——不携带 topSources
        TryEnqueue(TypeStunDropBurst, (int)Math.Min(int.MaxValue, StunWindowDelta(cfg.WindowSec)),
            cfg.StunDropCount, cfg.WindowSec, now, cfg.SilenceSec, topSources: null);

        await SendPendingAsync(cfg.Url, ct);
    }

    /// <summary>测试推送（POST /api/security/alert-test 载体）：立即发 type=test 载荷，
    /// 单次尝试（手动动作即时反馈；重试语义只属后台告警）。不占静默窗。</summary>
    internal async Task<bool> TriggerTestAsync(string url, CancellationToken ct = default)
    {
        var now = _time.GetLocalNow().UtcDateTime;
        var body = new Dictionary<string, object?>
        {
            ["schema"] = Schema,
            ["type"] = TypeTest,
            ["serverTs"] = Ts(now),
            ["detail"] = new Dictionary<string, object?>(), // 预留槽（07 §13.1 schema）
            ["ext"] = new Dictionary<string, object?> { ["source"] = "manual" },
        };
        try
        {
            using var resp = await _http.PostAsJsonAsync(url, body, ct).ConfigureAwait(false);
            return resp.IsSuccessStatusCode;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException
            or OperationCanceledException)
        {
            return false;
        }
    }

    /// <summary>内部计数快照（测试断言用）。</summary>
    internal (int Pending, IReadOnlyDictionary<string, DateTime> LastAlertAt) SnapshotState()
    {
        lock (_gate) return (_pending.Count, new Dictionary<string, DateTime>(_lastAlertAt));
    }

    private async Task TickSafeAsync(CancellationToken ct)
    {
        try { await TickOnceAsync(ct).ConfigureAwait(false); }
        catch (Exception ex) { _log?.LogWarning(ex, "AlertPusher 单轮判定异常（忽略，下轮重评）"); }
    }

    /// <summary>自动封禁判定（M5-08/SEC-73、07 §13.3）：LoginThrottle IP 维共享数据源——
    /// autoban_* 四键现读，窗内失败 ≥ N → AddAuto（封 duration）；仅新入列落 ip_auto_block
    /// （detail: ip/fails/windowSec——刷新与被 manual 压制不重复记，BlacklistStore 返回值承载）。</summary>
    private async Task EvaluateAutobanAsync(CancellationToken ct)
    {
        if (blacklist is null) return;
        bool enabled;
        int windowSec, failCount, durationSec;
        await using (var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false))
        {
            var cfg = new ServerConfigStore(db);
            enabled = cfg.GetBool("autoban_enabled");
            windowSec = cfg.GetInt("autoban_window_sec");
            failCount = cfg.GetInt("autoban_fail_count");
            durationSec = cfg.GetInt("autoban_duration_sec");
        }
        if (!enabled) return;
        foreach (var (ip, fails) in loginThrottle.SnapshotIpWindow(windowSec))
            if (fails >= failCount && await blacklist.AddAutoAsync(ip, durationSec, ct).ConfigureAwait(false))
                await (audit?.WriteAsync("ip_auto_block", detail: new { ip, fails, windowSec }, ct: ct)
                    ?? Task.CompletedTask).ConfigureAwait(false);
    }

    /// <summary>alert_* 七键现读（每 tick 一次库查——管理页 PUT 后 ≤30s 生效）。</summary>
    private async Task<AlertConfig> ReadConfigAsync(CancellationToken ct)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var cfg = new ServerConfigStore(db);
        return new AlertConfig(
            cfg.GetBool("alert_enabled"), cfg.Get("alert_webhook_url"), cfg.GetInt("alert_window_sec"),
            cfg.GetInt("alert_silence_sec"), cfg.GetInt("alert_login_fail_count"),
            cfg.GetInt("alert_register_count"), cfg.GetInt("alert_stun_drop_count"));
    }

    private sealed record AlertConfig(bool Enabled, string Url, int WindowSec, int SilenceSec,
        int LoginFailCount, int RegisterCount, int StunDropCount);

    /// <summary>阈值+静默窗判定 → 入待发队列（topSources 仅 login/register 携带前 3 名）。</summary>
    private void TryEnqueue(string type, int count, int threshold, int windowSec, DateTime now,
        int silenceSec, IReadOnlyList<(string Ip, int Count)>? topSources)
    {
        if (count < threshold) return;
        lock (_gate)
        {
            if (_lastAlertAt.TryGetValue(type, out var last) && now - last < TimeSpan.FromSeconds(silenceSec))
                return; // 静默窗内（阈值持续满足也静默，07 §13.1）
            _lastAlertAt[type] = now;
            var body = new Dictionary<string, object?>
            {
                ["schema"] = Schema,
                ["type"] = type,
                ["serverTs"] = Ts(now),
                ["window"] = new Dictionary<string, object?>
                {
                    ["from"] = Ts(now.AddSeconds(-windowSec)),
                    ["to"] = Ts(now),
                    ["seconds"] = windowSec,
                },
                ["count"] = count,
                ["threshold"] = threshold,
            };
            if (topSources is not null)
                body["topSources"] = topSources.Take(3)
                    .Select(s => new Dictionary<string, object?> { ["ip"] = s.Ip, ["count"] = s.Count })
                    .ToList();
            body["detail"] = new Dictionary<string, object?>(); // 预留槽（07 §13.1 schema）
            body["ext"] = new Dictionary<string, object?>();
            _pending.Add(new PendingAlert(type, body));
        }
    }

    /// <summary>派发待发（含重试）：成功即出队；失败 Attempts+1，达 3 轮丢弃+日志。</summary>
    private async Task SendPendingAsync(string url, CancellationToken ct)
    {
        List<PendingAlert> batch;
        lock (_gate) batch = [.. _pending];
        foreach (var p in batch)
        {
            bool ok;
            try
            {
                using var resp = await _http.PostAsJsonAsync(url, p.Body, ct).ConfigureAwait(false);
                ok = resp.IsSuccessStatusCode;
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException
                or OperationCanceledException)
            {
                ok = false;
            }
            lock (_gate)
            {
                if (ok) _pending.Remove(p);
                else if (++p.Attempts >= MaxAttempts)
                {
                    _pending.Remove(p);
                    _log?.LogWarning("告警丢弃（推送 {Attempts} 次失败）：type={Type} url={Url}",
                        p.Attempts, p.Type, url);
                }
            }
        }
    }

    /// <summary>STUN 累计采样：本 tick 增量=现值−上次采样（clamp ≥0），入环形队列。</summary>
    private void SampleStun()
    {
        var s = stun?.Guard.Snapshot();
        var total = s is null ? 0 : s.Rate + s.Auth + s.Circuit;
        var now = _time.GetLocalNow().UtcTicks;
        lock (_gate)
        {
            var delta = _lastStunTotal < 0 ? 0 : Math.Max(0, total - _lastStunTotal);
            _lastStunTotal = total;
            _stunDeltas.Enqueue((now, delta));
            // 容量兜底：清 24h 前样本（最大窗口 86400s，超出样本对任何合法窗口都不可见）
            var floor = now - TimeSpan.FromHours(24).Ticks;
            while (_stunDeltas.Count > 0 && _stunDeltas.Peek().Ticks < floor)
                _stunDeltas.Dequeue();
        }
    }

    private long StunWindowDelta(int windowSec)
    {
        var floor = _time.GetLocalNow().UtcTicks - (long)Math.Clamp(windowSec, 1, 86400) * TimeSpan.TicksPerSecond;
        lock (_gate) return _stunDeltas.Where(d => d.Ticks > floor).Sum(d => d.Delta);
    }

    private static string Ts(DateTime utc) => utc.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'");

    private sealed class PendingAlert(string type, Dictionary<string, object?> body)
    {
        public string Type { get; } = type;
        public Dictionary<string, object?> Body { get; } = body;
        public int Attempts { get; set; }
    }
}
