using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using P2P.Server.Data;
using P2P.Server.Services;
using Xunit;

namespace P2P.Server.Tests;

/// <summary>
/// M5-07 AlertPusher 单测（SEC-71、07 §13.1）：三类触发源阈值判定/静默窗/重试丢弃/
/// 开关现读 + 真实回环 webhook 线级验证（载荷 schema/type/window/count/threshold/topSources）。
/// 纯组件形态：FakeTimeProvider 驱动窗口算术；HTTP 经注入 stub handler（无端口绑定），
/// 唯线级用例起临时 Kestrel 收包。
/// </summary>
public sealed class AlertPusherTests : IDisposable
{
    private readonly TestDatabase _db = new();
    private readonly StubFactory _factory;
    private readonly FakeTimeProvider _time = new(DateTimeOffset.Parse("2026-10-23T00:00:00Z"));
    private readonly StubHandler _stub = new();
    private readonly LoginThrottle _throttle;
    private readonly RegistrationMetrics _metrics;
    private readonly AlertPusher _pusher;

    public AlertPusherTests()
    {
        _factory = new StubFactory(CreateDb);
        using (var init = _factory.CreateDbContext())
            DbInitializer.Initialize(init);
        _throttle = new LoginThrottle(time: _time);
        _metrics = new RegistrationMetrics(_time);
        _pusher = new AlertPusher(_factory, _throttle, _metrics, _time, http: new HttpClient(_stub));
        SetConfig("alert_enabled", "1");
        SetConfig("alert_webhook_url", "http://stub/hook");
        SetConfig("alert_login_fail_count", "3");
        SetConfig("alert_register_count", "2");
        SetConfig("alert_stun_drop_count", "200");
    }

    public void Dispose() => _db.Dispose();

    private AppDbContext CreateDb() => new(
        new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_db.DataSource).Options);

    private void SetConfig(string key, string value)
    {
        using var db = CreateDb();
        db.ServerConfig.Single(c => c.Key == key).Value = value;
        db.SaveChanges();
    }

    [Fact]
    public async Task 登录失败风暴_阈值触发_载荷字段断言()
    {
        _throttle.RecordFailure(LoginThrottle.DimIp, "203.0.113.7");
        _throttle.RecordFailure(LoginThrottle.DimIp, "203.0.113.7");
        _throttle.RecordFailure(LoginThrottle.DimIp, "198.51.100.9");

        await _pusher.TickOnceAsync();

        var req = Assert.Single(_stub.Received);
        Assert.Equal("http://stub/hook", req.Url);
        var body = req.Body;
        Assert.Equal("p2p.alert/v1", body.GetProperty("schema").GetString());
        Assert.Equal("login_fail_burst", body.GetProperty("type").GetString());
        Assert.Equal(3, body.GetProperty("count").GetInt32());        // 四入口 IP 维聚合
        Assert.Equal(3, body.GetProperty("threshold").GetInt32());
        Assert.Equal(300, body.GetProperty("window").GetProperty("seconds").GetInt32());
        Assert.Equal("2026-10-23T00:00:00Z", body.GetProperty("serverTs").GetString());
        Assert.Equal("2026-10-22T23:55:00Z", body.GetProperty("window").GetProperty("from").GetString());
        var top = body.GetProperty("topSources").EnumerateArray().ToList();
        Assert.Equal(2, top.Count);
        Assert.Equal("203.0.113.7", top[0].GetProperty("ip").GetString()); // 计数降序
        Assert.Equal(2, top[0].GetProperty("count").GetInt32());
        Assert.True(body.TryGetProperty("ext", out _));                    // 扩展位在
        Assert.True(body.TryGetProperty("detail", out _));                 // 预留槽在（07 §13.1 schema）
    }

    [Fact]
    public async Task 未达阈值_不推送()
    {
        _throttle.RecordFailure(LoginThrottle.DimIp, "203.0.113.7");
        _throttle.RecordFailure(LoginThrottle.DimIp, "203.0.113.7"); // 2 < 3

        await _pusher.TickOnceAsync();

        Assert.Empty(_stub.Received);
    }

    [Fact]
    public async Task 静默窗_窗口内不重复推送_过期后可再推()
    {
        for (var i = 0; i < 3; i++) _throttle.RecordFailure(LoginThrottle.DimIp, "203.0.113.7");
        await _pusher.TickOnceAsync();
        Assert.Single(_stub.Received);

        // 静默窗内（阈值持续满足也静默，07 §13.1）
        _time.Advance(TimeSpan.FromSeconds(10));
        await _pusher.TickOnceAsync();
        Assert.Single(_stub.Received);

        // 静默过期 + 计数仍在窗内（300s<1800s 静默窗大于判定窗）→ 需再记失败后重评
        _time.Advance(TimeSpan.FromSeconds(1801));
        for (var i = 0; i < 3; i++) _throttle.RecordFailure(LoginThrottle.DimIp, "203.0.113.7");
        await _pusher.TickOnceAsync();
        Assert.Equal(2, _stub.Received.Count);
    }

    [Fact]
    public async Task 推送失败_三轮重试后丢弃_不影响流程()
    {
        _stub.Respond = () => new HttpResponseMessage(HttpStatusCode.InternalServerError);
        for (var i = 0; i < 3; i++) _throttle.RecordFailure(LoginThrottle.DimIp, "203.0.113.7");

        await _pusher.TickOnceAsync(); // 尝试 1：入队即发，失败留队
        await _pusher.TickOnceAsync(); // 尝试 2
        await _pusher.TickOnceAsync(); // 尝试 3 → 丢弃+日志（不抛异常——TickOnceAsync 正常返回）
        Assert.Equal(3, _stub.Received.Count);
        Assert.Equal(0, _pusher.SnapshotState().Pending);

        // 恢复后新告警正常送达（静默过期后）
        _stub.Respond = () => new HttpResponseMessage(HttpStatusCode.OK);
        _time.Advance(TimeSpan.FromSeconds(1801));
        for (var i = 0; i < 3; i++) _throttle.RecordFailure(LoginThrottle.DimIp, "203.0.113.7");
        await _pusher.TickOnceAsync();
        Assert.Equal(4, _stub.Received.Count);
        Assert.Equal(0, _pusher.SnapshotState().Pending);
    }

    [Fact]
    public async Task 注册风暴_触发_topSources携带()
    {
        _metrics.Record("203.0.113.7");
        _metrics.Record("203.0.113.7");
        await _pusher.TickOnceAsync();

        var body = Assert.Single(_stub.Received).Body;
        Assert.Equal("register_burst", body.GetProperty("type").GetString());
        Assert.Equal(2, body.GetProperty("count").GetInt32());
        Assert.Equal(2, body.GetProperty("threshold").GetInt32());
        Assert.Equal("203.0.113.7",
            body.GetProperty("topSources")[0].GetProperty("ip").GetString());
    }

    [Fact]
    public async Task STUN丢弃风暴_窗口增量触发_无源维度()
    {
        SetConfig("alert_silence_sec", "0"); // 本用例关闭静默——直观测关闭期增量连续性
        await using var stun = new StunService(_factory, time: _time);
        var pusher = new AlertPusher(_factory, _throttle, _metrics, _time, stun,
            http: new HttpClient(_stub)); // 夹具 _pusher 未挂 stun——本用例本地装配
        await pusher.TickOnceAsync(); // 基线样本（首 tick 不计增量）
        Assert.Empty(_stub.Received);

        for (var i = 0; i < 200; i++) stun.Guard.CountAuth(); // 200 次认证丢弃（≥ 阈值）
        await pusher.TickOnceAsync();

        var body = Assert.Single(_stub.Received).Body;
        Assert.Equal("stun_drop_burst", body.GetProperty("type").GetString());
        Assert.Equal(200, body.GetProperty("count").GetInt32());
        Assert.False(body.TryGetProperty("topSources", out _)); // StunGuard 全局计数无源维度

        // 关闭期增量连续性（SampleStun 先于开关判定）：enabled=0 期间照常采样，恢复后并入窗口
        SetConfig("alert_enabled", "0");
        for (var i = 0; i < 200; i++) stun.Guard.CountAuth();
        await pusher.TickOnceAsync(); // 采样但不推送
        Assert.Single(_stub.Received);
        SetConfig("alert_enabled", "1");
        await pusher.TickOnceAsync(); // 窗口内增量累计 400 ≥ 200 → 再推
        Assert.Equal(2, _stub.Received.Count);
        Assert.Equal("stun_drop_burst", _stub.Received[1].Body.GetProperty("type").GetString());
        Assert.Equal(400, _stub.Received[1].Body.GetProperty("count").GetInt32());
    }

    [Fact]
    public async Task 开关关闭_不推送_库值现读即时生效()
    {
        SetConfig("alert_enabled", "0"); // 种子缺省即 0，此处显式回写
        for (var i = 0; i < 3; i++) _throttle.RecordFailure(LoginThrottle.DimIp, "203.0.113.7");
        await _pusher.TickOnceAsync();
        Assert.Empty(_stub.Received);

        SetConfig("alert_enabled", "1"); // 每 tick 现读（≤30s 生效，07 §13.1）
        await _pusher.TickOnceAsync();
        Assert.Single(_stub.Received);
    }

    [Fact]
    public async Task 真实HTTP_回环webhook收到告警载荷()
    {
        // 临时 Kestrel webhook 接收端（线级：真实 HttpClient→TCP→JSON 反序列化全链）；
        // 0=OS 分配端口，启动后自 app.Urls 回读（并行夹具零撞口）
        var received = new List<(string? ContentType, JsonElement Body)>();
        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        var app = builder.Build();
        app.MapPost("/hook", async (HttpContext ctx) =>
        {
            received.Add((ctx.Request.ContentType,
                await ctx.Request.ReadFromJsonAsync<JsonElement>()));
        });
        await app.StartAsync();
        var port = app.Urls.Select(u => Uri.TryCreate(u, UriKind.Absolute, out var x) ? x.Port : -1)
            .FirstOrDefault(p => p > 0);
        try
        {
            SetConfig("alert_webhook_url", $"http://127.0.0.1:{port}/hook");
            var pusher = new AlertPusher(_factory, _throttle, _metrics, _time); // 未注入 http=真 HttpClient
            for (var i = 0; i < 3; i++) _throttle.RecordFailure(LoginThrottle.DimIp, "203.0.113.9");
            await pusher.TickOnceAsync();

            var (contentType, body) = Assert.Single(received);
            Assert.StartsWith("application/json", contentType); // PostAsJson 带 charset 后缀
            Assert.Equal("p2p.alert/v1", body.GetProperty("schema").GetString());
            Assert.Equal("login_fail_burst", body.GetProperty("type").GetString());
            Assert.Equal(3, body.GetProperty("count").GetInt32());
            Assert.Equal(3, body.GetProperty("threshold").GetInt32());
            Assert.Equal(300, body.GetProperty("window").GetProperty("seconds").GetInt32());
        }
        finally
        {
            await app.StopAsync();
            await app.DisposeAsync();
        }
    }

    [Fact]
    public async Task TriggerTest_test载荷直发_不占静默窗()
    {
        Assert.True(await _pusher.TriggerTestAsync("http://stub/hook"));
        var body = Assert.Single(_stub.Received).Body;
        Assert.Equal("p2p.alert/v1", body.GetProperty("schema").GetString());
        Assert.Equal("test", body.GetProperty("type").GetString());
        Assert.Equal("manual", body.GetProperty("ext").GetProperty("source").GetString());
        Assert.Empty(_pusher.SnapshotState().LastAlertAt); // 不留静默痕迹

        // 接收端 5xx → false（SecurityApi 据此 502）
        _stub.Respond = () => new HttpResponseMessage(HttpStatusCode.BadGateway);
        Assert.False(await _pusher.TriggerTestAsync("http://stub/hook"));
    }

    // ── M5-08 自动封禁判定（SEC-73、07 §13.3：与告警通道同 tick、开关独立）──

    [Fact]
    public async Task 自动封禁_窗口失败达阈值_加auto条目与审计_刷新不重复记()
    {
        SetConfig("autoban_window_sec", "600");
        SetConfig("autoban_fail_count", "3");
        SetConfig("autoban_duration_sec", "3600");
        await using var blacklist = new BlacklistStore(_factory, _time);
        var audit = new AuditLogger(_factory, _time);
        var pusher = new AlertPusher(_factory, _throttle, _metrics, _time, blacklist: blacklist,
            http: new HttpClient(_stub), audit: audit);

        for (var i = 0; i < 3; i++) _throttle.RecordFailure(LoginThrottle.DimIp, "203.0.113.77");
        await pusher.TickOnceAsync();

        Assert.True(blacklist.IsBlocked("203.0.113.77"));
        var entry = Assert.Single(blacklist.Snapshot());
        Assert.Equal(BlacklistStore.SourceAuto, entry.Source);
        Assert.Equal(_time.GetLocalNow().UtcDateTime.AddHours(1),
            entry.ExpiresAtUtc!.Value, TimeSpan.FromSeconds(1)); // 封 autoban_duration_sec
        using (var db = CreateDb())
        {
            var row = Assert.Single(db.AuditLogs, a => a.Event == "ip_auto_block");
            Assert.Contains("203.0.113.77", row.Detail);
        }

        // 下一 tick 阈值仍满足 → 刷新（延长到期）不重复审计（首封行已是处置证据）
        _time.Advance(TimeSpan.FromSeconds(30));
        await pusher.TickOnceAsync();
        using (var db = CreateDb())
        {
            Assert.Single(db.AuditLogs, a => a.Event == "ip_auto_block");
            Assert.Single(blacklist.Snapshot());
        }
    }

    [Fact]
    public async Task 自动封禁_开关关_只关判定_未封不入列()
    {
        SetConfig("autoban_enabled", "0"); // 种子缺省 1，此处显式关
        SetConfig("autoban_fail_count", "3");
        await using var blacklist = new BlacklistStore(_factory, _time);
        var pusher = new AlertPusher(_factory, _throttle, _metrics, _time, blacklist: blacklist,
            http: new HttpClient(_stub));

        for (var i = 0; i < 5; i++) _throttle.RecordFailure(LoginThrottle.DimIp, "203.0.113.77"); // 超 阈值也不判
        await pusher.TickOnceAsync();
        Assert.False(blacklist.IsBlocked("203.0.113.77"));
    }

    /// <summary>stub HTTP handler：记录与应答可控（默认 200）。</summary>
    private sealed class StubHandler : HttpMessageHandler
    {
        public List<(string Url, JsonElement Body)> Received { get; } = [];
        public Func<HttpResponseMessage> Respond { get; set; } =
            () => new HttpResponseMessage(HttpStatusCode.OK);

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            await using var stream = await request.Content!.ReadAsStreamAsync(cancellationToken);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            Received.Add((request.RequestUri!.ToString(), doc.RootElement.Clone()));
            return Respond();
        }
    }
}
