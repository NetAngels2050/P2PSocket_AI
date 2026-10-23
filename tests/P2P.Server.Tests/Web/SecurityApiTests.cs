using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using P2P.Server.Data;
using P2P.Server.Services;
using P2P.Server.Web;
using Xunit;

namespace P2P.Server.Tests.Web;

/// <summary>
/// M5-07/08 安全中心 API（SEC-71/73、07 §13.1/§13.3、04 §3.2）：POST /api/security/alert-test——
/// 未配 URL 400{1001}；已配 URL 200+type=test 载荷直达 webhook（stub handler 断言）；
/// 接收端失败 502{5003}（SERVER_UNREACHABLE 复用——5004 v1.67 复用同法）。
/// M5-08：POST/DELETE /api/security/blacklist（manual 加黑/解封+处置审计 ip_block/ip_unblock）+
/// Web 面中间件（认证之前 403{2003}——被封 IP 全端点拒，解封即恢复）。
/// 最小夹具（同 AdminSystemApiTests 形态；AlertPusher 注入 stub http）。
/// </summary>
public sealed class SecurityApiTests : IAsyncLifetime
{
    private readonly TestDatabase _db = new();
    private readonly StubHandler _stub = new();
    private ServerWebHostService _web = null!;
    private HttpClient _http = null!;
    private IDbContextFactory<AppDbContext> _factory = null!;
    private BlacklistStore _blacklist = null!;
    private AuditLogger _audit = null!;

    public async Task InitializeAsync()
    {
        _factory = new StubFactory(CreateDb);
        using (var init = _factory.CreateDbContext())
            DbInitializer.Initialize(init);

        _audit = new AuditLogger(_factory);
        var registry = new DeviceRegistry();
        var invalidation = new InvalidationPusher(_factory, registry);
        var pusher = new DeviceListPusher(_factory, registry);
        var groups = new GroupService(_factory, registry, audit: _audit, pusher, invalidation);
        var admin = new AdminService(_factory, registry, _audit, invalidation, listPusher: pusher);
        var alert = new AlertPusher(_factory, new LoginThrottle(), new RegistrationMetrics(),
            http: new HttpClient(_stub));
        _blacklist = new BlacklistStore(_factory);

        var options = new ServerOptions { Listen = { Web = Random.Shared.Next(21000, 24000) } };
        _web = new ServerWebHostService(options, TimeProvider.System,
            new AdminSessionStore(TimeProvider.System), _factory, _audit, admin, registry, groups,
            alertPusher: alert, blacklist: _blacklist)
        {
            WebRootOverride = Path.Combine(Path.GetTempPath(), $"p2p-no-webroot-{Guid.NewGuid():N}"),
        };
        await _web.StartAsync(CancellationToken.None);

        _http = new HttpClient(new HttpClientHandler { CookieContainer = new CookieContainer() })
        {
            BaseAddress = new Uri($"http://127.0.0.1:{options.Listen.Web}/"),
        };
        Assert.Equal(HttpStatusCode.OK,
            (await _http.PostAsJsonAsync("/api/auth/login", new { username = "admin", password = "admin" })).StatusCode);
    }

    public async Task DisposeAsync()
    {
        _http.Dispose();
        await _web.StopAsync(CancellationToken.None);
        _db.Dispose();
    }

    private AppDbContext CreateDb() => new(
        new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_db.DataSource).Options);

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
