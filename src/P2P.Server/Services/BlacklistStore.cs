using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using P2P.Server.Data;

namespace P2P.Server.Services;

/// <summary>一条黑名单条目（内存权威态；持久 DTO 同形 camelCase，03 §2.8 隐藏键 ip_blacklist）。</summary>
/// <param name="Ip">来源 IP（字符串键——IPv4/IPv6 皆可）。</param>
/// <param name="Reason">封禁原因（manual 可带；auto 承接被覆盖前值，缺省空）。</param>
/// <param name="Source">manual（永久）/ auto（按 expiresAtUtc 过期）。</param>
/// <param name="CreatedAtUtc">入列时刻（auto 刷新到期时保留首封时刻）。</param>
/// <param name="ExpiresAtUtc">manual 恒 null（永久）；auto=入列+duration。</param>
public sealed record BlacklistEntry(
    string Ip, string Reason, string Source, DateTime CreatedAtUtc, DateTime? ExpiresAtUtc);

/// <summary>
/// IP 黑名单两层存储（M5-08/SEC-73、FR-S-828、07 §13.3）：内存 dict（权威——四面 O(1) 查询、
/// 热生效）+ server_config 隐藏键 <c>ip_blacklist</c> JSON 持久（写穿——管理/自动封禁动作即写库，
/// 重启 ctor 恢复；不进 ConfigDefaults/管理页白名单，编辑面=/api/security/blacklist 专用 API）。
/// manual 永久且覆盖同 IP auto（升级）；manual 解封即删行（auto 到期自动消失：查询点惰性判定
/// +30s 清扫兜底）。命中不逐条审计（自我 DoS 向量，OQ-22①）——per-面命中计数器内存态暴露
/// 安全中心（M5-09），处置审计（ip_block/ip_unblock/ip_auto_block）由动作发起方落。
/// </summary>
public sealed class BlacklistStore : IAsyncDisposable
{
    public const string SourceManual = "manual";
    public const string SourceAuto = "auto";
    public const string ConfigKey = "ip_blacklist";

    /// <summary>四面命中计数键（07 §13.3 四面表；内存态重启清零）。</summary>
    public const string FaceControl = "control";
    public const string FaceStun = "stun";
    public const string FaceRelay = "relay";
    public const string FaceWeb = "web";

    private static readonly TimeSpan SweepInterval = TimeSpan.FromSeconds(30);
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly IDbContextFactory<AppDbContext> _dbFactory;
    private readonly TimeProvider _time;
    private readonly Lock _gate = new();
    private readonly Dictionary<string, BlacklistEntry> _entries = []; // ip → 条目（内存权威）
    private readonly Dictionary<string, long> _hits = [];               // face → 命中计数
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _sweeper;
    private int _disposed; // 宿主停机与容器释放各调一次（幂等——StunService 同款）

    public BlacklistStore(IDbContextFactory<AppDbContext> dbFactory, TimeProvider? time = null)
    {
        _dbFactory = dbFactory;
        _time = time ?? TimeProvider.System;
        // ctor 同步恢复（StunService ctor 读 public_addr 同款先例）：行缺失=空名单（按需创建）
        using var db = _dbFactory.CreateDbContext();
        var row = db.ServerConfig.AsNoTracking().SingleOrDefault(c => c.Key == ConfigKey);
        if (row is { Value.Length: > 0 })
            foreach (var e in JsonSerializer.Deserialize<List<BlacklistEntry>>(row.Value, JsonOpts) ?? [])
                _entries[e.Ip] = e;
        _sweeper = Task.Run(() => SweepAsync(_cts.Token));
    }

    /// <summary>封禁判定（四面热路径 O(1)）：过期 auto 条目惰性视为未命中（行移除由 30s 清扫兜底）。</summary>
    public bool IsBlocked(string ip)
    {
        lock (_gate)
            return _entries.TryGetValue(ip, out var e)
                && (e.ExpiresAtUtc is null || e.ExpiresAtUtc > _time.GetLocalNow().UtcDateTime);
    }

    /// <summary>记一次面命中（OQ-22①：不逐条审计——计数器供安全中心）。</summary>
    public void CountHit(string face)
    {
        lock (_gate) _hits[face] = _hits.GetValueOrDefault(face) + 1;
    }

    /// <summary>per-面命中计数快照（安全中心/测试）。</summary>
    public IReadOnlyDictionary<string, long> HitSnapshot()
    {
        lock (_gate) return new Dictionary<string, long>(_hits);
    }

    /// <summary>当前生效名单（过期条目不出；安全中心 M5-09 消费）。</summary>
    public List<BlacklistEntry> Snapshot()
    {
        var now = _time.GetLocalNow().UtcDateTime;
        lock (_gate)
            return [.. _entries.Values
                .Where(e => e.ExpiresAtUtc is null || e.ExpiresAtUtc > now)
                .OrderBy(e => e.Ip, StringComparer.Ordinal)];
    }

    /// <summary>手动加黑（POST /api/security/blacklist）：永久条目——同 IP 已有 auto 覆盖升级，
    /// 已有 manual 刷新原因；写穿持久。审计 ip_block 由 API 层落。</summary>
    public async Task<BlacklistEntry> BlockManualAsync(string ip, string? reason, CancellationToken ct = default)
    {
        BlacklistEntry entry;
        lock (_gate)
        {
            var now = _time.GetLocalNow().UtcDateTime;
            entry = new BlacklistEntry(ip, reason ?? "", SourceManual, now, ExpiresAtUtc: null);
            _entries[ip] = entry; // 覆盖同 IP auto（升级为永久，07 §13.3）
        }
        await PersistAsync(ct).ConfigureAwait(false);
        return entry;
    }

    /// <summary>自动封禁条目（AlertPusher tick 判定载体）：manual 已在不覆盖（manual 优先）；
    /// 未过期 auto 刷新到期时刻（持续爆破持续封）。返回 true=新入列（调用方据此落 ip_auto_block 审计，
    /// 刷新/被 manual 压制不重复记）。</summary>
    public async Task<bool> AddAutoAsync(string ip, int durationSec, CancellationToken ct = default)
    {
        bool added;
        lock (_gate)
        {
            var now = _time.GetLocalNow().UtcDateTime;
            if (_entries.TryGetValue(ip, out var e) && e.Source == SourceManual)
                return false; // manual 优先：auto 判定不改写永久条目
            var expires = now.AddSeconds(Math.Clamp(durationSec, 1, 86400));
            added = e is null; // 刷新（延长）不入审计——首封行已是处置证据
            _entries[ip] = new BlacklistEntry(ip, e?.Reason ?? "", SourceAuto, e?.CreatedAtUtc ?? now, expires);
        }
        await PersistAsync(ct).ConfigureAwait(false);
        return added;
    }

    /// <summary>解封（DELETE /api/security/blacklist/{ip}）：manual/auto 皆删行（auto 提前解封=管理员
    /// 显式动作）；返回是否存在。审计 ip_unblock 由 API 层落。</summary>
    public async Task<bool> RemoveAsync(string ip, CancellationToken ct = default)
    {
        bool removed;
        lock (_gate) removed = _entries.Remove(ip);
        if (removed) await PersistAsync(ct).ConfigureAwait(false);
        return removed;
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _cts.Cancel();
        try { await _sweeper.ConfigureAwait(false); } catch { }
        _cts.Dispose();
    }

    /// <summary>30s 清扫：过期 auto 行移除+持久同步（查询点惰性判定之外的兜底——安全中心视图与
    /// 持久层不留死行）。</summary>
    private async Task SweepAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(SweepInterval, _time);
        try
        {
            while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
                if (RemoveExpired()) await PersistAsync(ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { /* 停机 */ }
    }

    private bool RemoveExpired()
    {
        lock (_gate)
        {
            var now = _time.GetLocalNow().UtcDateTime;
            var expired = _entries.Where(kv => kv.Value.ExpiresAtUtc <= now).Select(kv => kv.Key).ToList();
            foreach (var ip in expired) _entries.Remove(ip);
            return expired.Count > 0;
        }
    }

    /// <summary>写穿持久：整名单 JSON 落隐藏键（行不存在则创建——ConfigDefaults 之外按需建）。</summary>
    private async Task PersistAsync(CancellationToken ct)
    {
        List<BlacklistEntry> snapshot;
        lock (_gate) snapshot = [.. _entries.Values];
        await using var db = await _dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var row = await db.ServerConfig.SingleOrDefaultAsync(c => c.Key == ConfigKey, ct).ConfigureAwait(false);
        var json = JsonSerializer.Serialize(snapshot, JsonOpts);
        if (row is null)
            db.ServerConfig.Add(new ServerConfigEntry { Key = ConfigKey, Value = json });
        else
            row.Value = json;
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }
}
