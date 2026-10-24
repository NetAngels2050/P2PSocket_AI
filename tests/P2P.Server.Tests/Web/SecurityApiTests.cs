using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using P2P.Core.Crypto;
using P2P.Server.Data;
using P2P.Server.Services;
using P2P.Server.Web;
using Xunit;

namespace P2P.Server.Tests.Web;

/// <summary>
/// M5-07/08/09 安全中心 API（SEC-71/72/73、07 §13、04 §3.2）：POST /api/security/alert-test——
/// 未配 URL 400{1001}；已配 URL 200+type=test 载荷直达 webhook（stub handler 断言）；
/// 接收端失败 502{5003}（SERVER_UNREACHABLE 复用——5004 v1.67 复用同法）。
/// M5-08：POST/DELETE /api/security/blacklist（manual 加黑/解封+处置审计 ip_block/ip_unblock）+
/// Web 面中间件（认证之前 403{2003}——被封 IP 全端点拒，解封即恢复）。
/// M5-09：GET /api/security/overview（今日=UTC 日界/近 7 天=滚动 168h 时间窗聚合口径——fake 时钟
/// 固定窗口边界；黑名单快照与四面命中/autoban 四键现值/注册开关）+ POST /api/security/lockdown
/// （真 ControlServer 双裸连接 → kicked=2 + 双 EOF + 审计 security_lockdown——07 §13.4 不设拒连窗）。
/// 最小夹具（同 AdminSystemApiTests 形态；AlertPusher 注入 stub http）。
/// </summary>
public sealed class SecurityApiTests : IAsyncLifetime
{
    private readonly TestDatabase _db = new();
    private readonly StubHandler _stub = new();
    private readonly FakeTimeProvider _time = new(DateTimeOffset.Parse("2026-10-23T12:00:00Z"));
    private ServerWebHostService _web = null!;
    private HttpClient _http = null!;
    private IDbContextFactory<AppDbContext> _factory = null!;
    private BlacklistStore _blacklist = null!;
    private AuditLogger _audit = null!;
    private ControlServer _control = null!;

    public async Task InitializeAsync()
    {
        _factory = new StubFactory(CreateDb);
        using (var init = _factory.CreateDbContext())
            DbInitializer.Initialize(init);

        _audit = new AuditLogger(_factory, _time);
        var registry = new DeviceRegistry();
        var invalidation = new InvalidationPusher(_factory, registry);
        var pusher = new DeviceListPusher(_factory, registry);
        var groups = new GroupService(_factory, registry, audit: _audit, pusher, invalidation);
        var admin = new AdminService(_factory, registry, _audit, invalidation, listPusher: pusher);
        var alert = new AlertPusher(_factory, new LoginThrottle(), new RegistrationMetrics(),
            http: new HttpClient(_stub));
        _blacklist = new BlacklistStore(_factory);
        _control = new ControlServer(_factory, registry, (_, _) => Task.CompletedTask, time: _time);
        await _control.StartAsync(new IPEndPoint(IPAddress.Loopback, 0));

        var options = new ServerOptions { Listen = { Web = 0 } }; // 0=OS 分配：启动后 _web.BoundPort 回读（并行夹具零撞口）
        _web = new ServerWebHostService(options, _time,
            new AdminSessionStore(TimeProvider.System), _factory, _audit, admin, registry, groups,
            alertPusher: alert, blacklist: _blacklist, control: _control)
        {
            WebRootOverride = Path.Combine(Path.GetTempPath(), $"p2p-no-webroot-{Guid.NewGuid():N}"),
        };
        await _web.StartAsync(CancellationToken.None);

        _http = new HttpClient(new HttpClientHandler { CookieContainer = new CookieContainer() })
        {
            BaseAddress = new Uri($"http://127.0.0.1:{_web.BoundPort}/"),
        };
        Assert.Equal(HttpStatusCode.OK,
            (await _http.PostAsJsonAsync("/api/auth/login", new { username = "admin", password = "admin" })).StatusCode);
    }

    public async Task DisposeAsync()
    {
        _http.Dispose();
        await _web.StopAsync(CancellationToken.None);
        await _control.DisposeAsync();
        await _blacklist.DisposeAsync();
        _db.Dispose();
    }

    private AppDbContext CreateDb() => new(
        new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_db.DataSource).Options);

    /// <summary>裸宿主启动后从 Kestrel 解析地址回读实际端口（Web=0 时 OS 分配）。</summary>
    private static int BoundPortOf(WebApplication app)
        => app.Urls.Select(u => Uri.TryCreate(u, UriKind.Absolute, out var x) ? x.Port : -1)
            .FirstOrDefault(p => p > 0);

    private async Task<(HttpStatusCode Status, JsonElement Body)> PostAlertTestAsync()
    {
        var resp = await _http.PostAsync("/api/security/alert-test", null);
        return (resp.StatusCode,
            JsonSerializer.Deserialize<JsonElement>(await resp.Content.ReadAsStreamAsync()));
    }

    [Fact]
    public async Task 未配URL_400参数错误()
    {
        var (status, body) = await PostAlertTestAsync(); // 种子 alert_webhook_url=空
        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal(1001, body.GetProperty("code").GetInt32());
        Assert.Contains("alert_webhook_url", body.GetProperty("message").GetString());
        Assert.Empty(_stub.Received);
    }

    [Fact]
    public async Task 已配URL_200_test载荷直达webhook()
    {
        await using (var db = CreateDb())
        {
            db.ServerConfig.Single(c => c.Key == "alert_webhook_url").Value = "http://stub/hook";
            db.SaveChanges();
        }

        var (status, body) = await PostAlertTestAsync();
        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Equal(0, body.GetProperty("code").GetInt32());
        var payload = Assert.Single(_stub.Received);
        Assert.Equal("p2p.alert/v1", payload.GetProperty("schema").GetString());
        Assert.Equal("test", payload.GetProperty("type").GetString());
        Assert.Equal("manual", payload.GetProperty("ext").GetProperty("source").GetString());
    }

    [Fact]
    public async Task 接收端失败_502复用5003语义()
    {
        await using (var db = CreateDb())
        {
            db.ServerConfig.Single(c => c.Key == "alert_webhook_url").Value = "http://stub/hook";
            db.SaveChanges();
        }
        _stub.Respond = () => new HttpResponseMessage(HttpStatusCode.InternalServerError);

        var (status, body) = await PostAlertTestAsync();
        Assert.Equal(HttpStatusCode.BadGateway, status);
        Assert.Equal(5003, body.GetProperty("code").GetInt32());
        Assert.Contains("接收端未响应", body.GetProperty("message").GetString());
    }

    // ── M5-08 IP 黑名单（SEC-73、07 §13.3）────────────────────────────

    private async Task<(HttpStatusCode Status, JsonElement Body)> PostBlacklistAsync(object payload)
    {
        var resp = await _http.PostAsJsonAsync("/api/security/blacklist", payload);
        return (resp.StatusCode,
            JsonSerializer.Deserialize<JsonElement>(await resp.Content.ReadAsStreamAsync()));
    }

    [Fact]
    public async Task 加黑_非法IP_400参数错误()
    {
        var (status, body) = await PostBlacklistAsync(new { ip = "not-an-ip" });
        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal(1001, body.GetProperty("code").GetInt32());
        Assert.Empty(_blacklist.Snapshot());
    }

    [Fact]
    public async Task 加黑_合法IP_200_条目manual永久_审计ip_block()
    {
        var (status, body) = await PostBlacklistAsync(new { ip = "203.0.113.7", reason = "扫描探测" });
        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Equal(0, body.GetProperty("code").GetInt32());

        var entry = Assert.Single(_blacklist.Snapshot());
        Assert.Equal("203.0.113.7", entry.Ip);
        Assert.Equal(BlacklistStore.SourceManual, entry.Source);
        Assert.Null(entry.ExpiresAtUtc); // manual 永久
        Assert.True(_blacklist.IsBlocked("203.0.113.7"));

        await using var db = CreateDb();
        var row = db.AuditLogs.Single(a => a.Event == "ip_block");
        var detail = JsonDocument.Parse(row.Detail!).RootElement; // detail 序列化转义非 ASCII——按 JSON 断言
        Assert.Equal("203.0.113.7", detail.GetProperty("ip").GetString());
        Assert.Equal("扫描探测", detail.GetProperty("reason").GetString());
    }

    [Fact]
    public async Task 解封_条目不存在_404()
    {
        var resp = await _http.DeleteAsync("/api/security/blacklist/203.0.113.7");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        var body = JsonSerializer.Deserialize<JsonElement>(await resp.Content.ReadAsStreamAsync());
        Assert.Equal(1002, body.GetProperty("code").GetInt32());
    }

    [Fact]
    public async Task Web面_封禁后全端点403_认证之前_解封即恢复()
    {
        // 封 127.0.0.1（本测试客户端源 IP）：已登录会话也应被拒——中间件在认证之前（07 §13.3）
        var (status, _) = await PostBlacklistAsync(new { ip = "127.0.0.1" });
        Assert.Equal(HttpStatusCode.OK, status);

        var resp = await _http.GetAsync("/api/system/config"); // 携带有效会话 Cookie 仍 403
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        var body = JsonSerializer.Deserialize<JsonElement>(await resp.Content.ReadAsStreamAsync());
        Assert.Equal(2003, body.GetProperty("code").GetInt32()); // FORBIDDEN（04 §5 表内既有码）
        Assert.Equal(1, _blacklist.HitSnapshot()[BlacklistStore.FaceWeb]);

        // 解封端点同被拦（全端点语义——同 IP 自助解封不通，须他面/安全中心处置）
        Assert.Equal(HttpStatusCode.Forbidden,
            (await _http.DeleteAsync("/api/security/blacklist/127.0.0.1")).StatusCode);

        // 直调 store 解封（他面处置语义）→ Web 即恢复（会话未被破坏，正常 200 而非 401）
        Assert.True(await _blacklist.RemoveAsync("127.0.0.1"));
        Assert.Equal(HttpStatusCode.OK, (await _http.GetAsync("/api/system/config")).StatusCode);
    }

    // ── M5-09 安全中心（SEC-72、07 §13.2/§13.4）──────────────────────

    private async Task<JsonElement> GetOverviewAsync()
    {
        var resp = await _http.GetAsync("/api/security/overview");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = JsonSerializer.Deserialize<JsonElement>(await resp.Content.ReadAsStreamAsync());
        Assert.Equal(0, body.GetProperty("code").GetInt32());
        return body.GetProperty("data");
    }

    private static AuditLog AuditRow(string ev, string tsUtc) =>
        new() { Ts = DateTime.Parse(tsUtc, CultureInfo.InvariantCulture), Event = ev };

    [Fact]
    public async Task Overview_时间窗聚合口径_今日UTC日界与滚动7天_事件族分桶()
    {
        // 血缘=audit_logs 时间窗查询（07 §13.2）：fake now=2026-10-23T12:00Z ⇒
        // todayFloor=10-23T00:00Z、weekFloor=10-16T12:00Z；今日集为近 7 天子集
        await using (var db = CreateDb())
        {
            db.AuditLogs.AddRange(
                AuditRow("login_failed", "2026-10-23T11:00:00Z"),
                AuditRow("login_failed", "2026-10-23T09:30:00Z"),
                AuditRow("admin_login_fail", "2026-10-23T08:00:00Z"),
                AuditRow("login_failed", "2026-10-20T12:00:00Z"),
                AuditRow("login_failed", "2026-10-15T00:00:00Z"), // 8 天前——两窗皆外
                AuditRow("register", "2026-10-23T10:00:00Z"),
                AuditRow("register_recover", "2026-10-21T12:00:00Z"),
                AuditRow("punch_deny", "2026-10-22T12:00:00Z"),
                AuditRow("group_join_deny", "2026-10-23T07:00:00Z"),
                AuditRow("mapping_deny", "2026-10-17T00:00:00Z"),
                AuditRow("login", "2026-10-23T11:30:00Z")); // 非本页事件（登录成功）——不计
            await db.SaveChangesAsync();
        }

        var data = await GetOverviewAsync();
        var today = data.GetProperty("today");
        Assert.Equal(3, today.GetProperty("loginFail").GetInt32()); // 0x21+admin 两族
        Assert.Equal(1, today.GetProperty("register").GetInt32());
        Assert.Equal(1, today.GetProperty("deny").GetInt32()); // group_join_deny（其余在周窗）
        var week = data.GetProperty("week");
        Assert.Equal(4, week.GetProperty("loginFail").GetInt32());
        Assert.Equal(2, week.GetProperty("register").GetInt32());
        Assert.Equal(3, week.GetProperty("deny").GetInt32()); // punch+group_join+mapping
    }

    [Fact]
    public async Task Overview_黑名单快照与四面命中_自动封禁现值_注册开关()
    {
        Assert.True(await _blacklist.AddAutoAsync("198.51.100.10", 3600));
        await _blacklist.BlockManualAsync("203.0.113.50", "扫描", CancellationToken.None);
        _blacklist.CountHit(BlacklistStore.FaceControl);
        _blacklist.CountHit(BlacklistStore.FaceControl);
        _blacklist.CountHit(BlacklistStore.FaceWeb);

        var data = await GetOverviewAsync();
        var list = data.GetProperty("blacklist");
        Assert.Equal(2, list.GetArrayLength());
        Assert.Equal("198.51.100.10", list[0].GetProperty("ip").GetString());
        Assert.Equal("auto", list[0].GetProperty("source").GetString());
        Assert.Equal("manual", list[1].GetProperty("source").GetString());

        var hits = data.GetProperty("hits"); // 只含已触碰面（快照语义——前端缺省 0）
        Assert.Equal(2, hits.GetProperty("control").GetInt32());
        Assert.Equal(1, hits.GetProperty("web").GetInt32());
        Assert.False(hits.TryGetProperty("stun", out _));

        var autoban = data.GetProperty("autoban"); // 四键种子现值回显
        Assert.True(autoban.GetProperty("enabled").GetBoolean());
        Assert.Equal(600, autoban.GetProperty("windowSec").GetInt32());
        Assert.Equal(20, autoban.GetProperty("failCount").GetInt32());
        Assert.Equal(3600, autoban.GetProperty("durationSec").GetInt32());
        Assert.True(data.GetProperty("registrationOpen").GetBoolean());

        var stun = data.GetProperty("stun"); // 未注 STUN 件——零值快照 + since null
        Assert.Equal(0, stun.GetProperty("rate").GetInt32());
        Assert.Equal(JsonValueKind.Null, stun.GetProperty("since").ValueKind);

        var enc = data.GetProperty("encryption"); // M5-13（SEC-83）：未注 cipher（未配 masterKey）——enabled=false
        Assert.False(enc.GetProperty("enabled").GetBoolean());
        Assert.Equal(0, enc.GetProperty("decryptFailures").GetInt32());
    }

    [Fact]
    public async Task Overview_静态加密状态_cipher在位透出解密失败计数()
    {
        // 独立裸宿主（同 ExportTs 形态——SecurityApi 直挂；与 _web 的未注 cipher 形态互补）
        var cipher = new DeviceSecretCipher(
            Convert.ToHexString(RandomGenerator.Bytes(32)).ToLowerInvariant());
        cipher.DecryptOrRaw(new byte[61]); // keyTag 0 不匹配 → 凭据失效口径计数+1（OQ-22②）

        var factory = ServerDatabase.CreateFactoryFromDataSource(_db.DataSource, cipher);
        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0"); // 0=OS 分配：启动后 app.Urls 回读（并行夹具零撞口）
        var app = builder.Build();
        new SecurityApi(factory, _time, _audit, cipher: cipher).Map(app);
        await app.StartAsync();
        var port = BoundPortOf(app);
        try
        {
            using var http = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{port}") };
            var resp = await http.GetAsync("/api/security/overview");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            var body = JsonSerializer.Deserialize<JsonElement>(await resp.Content.ReadAsStreamAsync());
            var enc = body.GetProperty("data").GetProperty("encryption");
            Assert.True(enc.GetProperty("enabled").GetBoolean());
            Assert.Equal(1, enc.GetProperty("decryptFailures").GetInt32());
        }
        finally { await app.StopAsync(); }
    }

    [Fact]
    public async Task Lockdown_断开全部控制会话_审计security_lockdown()
    {
        using var a = new TcpClient();
        using var b = new TcpClient();
        await a.ConnectAsync(_control.LocalEndPoint!);
        await b.ConnectAsync(_control.LocalEndPoint!);
        for (var i = 0; i < 100 && _control.Sessions.Count < 2; i++)
            await Task.Delay(20); // accept→会话入表异步
        Assert.Equal(2, _control.Sessions.Count);

        var resp = await _http.PostAsync("/api/security/lockdown", null);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = JsonSerializer.Deserialize<JsonElement>(await resp.Content.ReadAsStreamAsync());
        Assert.Equal(2, body.GetProperty("data").GetProperty("kicked").GetInt32());

        // 两连接均被服务端断开（EOF=0）
        Assert.Equal(0, await a.GetStream().ReadAsync(new byte[16]));
        Assert.Equal(0, await b.GetStream().ReadAsync(new byte[16]));

        await using var db = CreateDb();
        var row = db.AuditLogs.AsNoTracking().Single(r => r.Event == "security_lockdown");
        Assert.Contains("\"kicked\":2", row.Detail); // 纯 ASCII 属性可直 Contains（非 ASCII 须 JsonDocument）
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        public List<JsonElement> Received { get; } = [];
        public Func<HttpResponseMessage> Respond { get; set; } =
            () => new HttpResponseMessage(HttpStatusCode.OK);

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            await using var stream = await request.Content!.ReadAsStreamAsync(cancellationToken);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            Received.Add(doc.RootElement.Clone());
            return Respond();
        }
    }
}
