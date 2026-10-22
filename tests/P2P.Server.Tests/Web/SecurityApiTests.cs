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
/// M5-07 安全中心首件 API（SEC-71、07 §13.1、04 §3.2）：POST /api/security/alert-test——
/// 未配 URL 400{1001}；已配 URL 200+type=test 载荷直达 webhook（stub handler 断言）；
/// 接收端失败 502{5003}（SERVER_UNREACHABLE 复用——5004 v1.67 复用同法）。
/// 最小夹具（同 AdminSystemApiTests 形态；AlertPusher 注入 stub http）。
/// </summary>
public sealed class SecurityApiTests : IAsyncLifetime
{
    private readonly TestDatabase _db = new();
    private readonly StubHandler _stub = new();
    private ServerWebHostService _web = null!;
    private HttpClient _http = null!;
    private IDbContextFactory<AppDbContext> _factory = null!;

    public async Task InitializeAsync()
    {
        _factory = new StubFactory(CreateDb);
        using (var init = _factory.CreateDbContext())
            DbInitializer.Initialize(init);

        var audit = new AuditLogger(_factory);
        var registry = new DeviceRegistry();
        var invalidation = new InvalidationPusher(_factory, registry);
        var pusher = new DeviceListPusher(_factory, registry);
        var groups = new GroupService(_factory, registry, audit, pusher, invalidation);
        var admin = new AdminService(_factory, registry, audit, invalidation, listPusher: pusher);
        var alert = new AlertPusher(_factory, new LoginThrottle(), new RegistrationMetrics(),
            http: new HttpClient(_stub));

        var options = new ServerOptions { Listen = { Web = Random.Shared.Next(21000, 24000) } };
        _web = new ServerWebHostService(options, TimeProvider.System,
            new AdminSessionStore(TimeProvider.System), _factory, audit, admin, registry, groups,
            alertPusher: alert)
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
