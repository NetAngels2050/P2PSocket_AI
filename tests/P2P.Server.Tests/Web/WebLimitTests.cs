using System.Net;
using System.Net.Sockets;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Time.Testing;
using P2P.Server.Data;
using P2P.Server.Services;
using P2P.Server.Web;
using Xunit;

namespace P2P.Server.Tests.Web;

/// <summary>
/// M5-10/SEC-64 管理 Web 并发连接上限（07 §12、03 §2.8 web_max_connections——启动期读入
/// Kestrel Limits.MaxConcurrentConnections，改动须重启）：上限内正常应答；占满额度后新连接被拒；
/// 连接释放（对端断开）后额度回收恢复。裸 TCP 占位（不发 HTTP——Kestrel accept 即计入）。
/// </summary>
public sealed class WebLimitTests : IAsyncLifetime
{
    private readonly TestDatabase _db = new();
    private readonly FakeTimeProvider _time = new(DateTimeOffset.Parse("2026-10-23T12:00:00Z"));
    private ServerWebHostService _web = null!;
    private IDbContextFactory<AppDbContext> _factory = null!;
    private HttpClient _http = null!;

    public async Task InitializeAsync()
    {
        _factory = new StubFactory(CreateDb);
        using (var init = _factory.CreateDbContext())
        {
            DbInitializer.Initialize(init);
            init.ServerConfig.Single(c => c.Key == "web_max_connections").Value = "1"; // 最小上限便于占满
            init.SaveChanges();
        }

        var registry = new DeviceRegistry();
        var audit = new AuditLogger(_factory, _time);
        var invalidation = new InvalidationPusher(_factory, registry);
        var pusher = new DeviceListPusher(_factory, registry);
        var groups = new GroupService(_factory, registry, audit: audit, pusher, invalidation);
        var admin = new AdminService(_factory, registry, audit, invalidation, listPusher: pusher);

        // 端口带 28000-33000：与其他 Web 宿主夹具带（21000-27000）不相交——
        // 全解决方案并行下随机端口偶发同口绑定（AddressInUse 瞬断）从本类消除
        var options = new ServerOptions { Listen = { Web = Random.Shared.Next(28000, 33000) } };
        _web = new ServerWebHostService(options, _time,
            new AdminSessionStore(TimeProvider.System), _factory, audit, admin, registry, groups)
        {
            WebRootOverride = Path.Combine(Path.GetTempPath(), $"p2p-no-webroot-{Guid.NewGuid():N}"),
        };
        await _web.StartAsync(CancellationToken.None);

        _http = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{options.Listen.Web}/") };
        _http.DefaultRequestHeaders.ConnectionClose = true; // 每请求独立连接——防 keep-alive 复用绕开额度观测
    }

    public async Task DisposeAsync()
    {
        _http.Dispose();
        await _web.StopAsync(CancellationToken.None);
        _db.Dispose();
    }

    private AppDbContext CreateDb() => new(
        new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_db.DataSource).Options);

    /// <summary>GET 未鉴权端点：任何 HTTP 应答（401）即证明连接可建；连接被拒=请求异常。</summary>
    private async Task<HttpStatusCode?> GetStatusAsync(int timeoutMs = 3000)
    {
        using var cts = new CancellationTokenSource(timeoutMs);
        try
        {
            using var resp = await _http.GetAsync("/api/system/config", cts.Token);
            return resp.StatusCode;
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException)
        {
            return null; // 连接被拒/超时（Kestrel 额度满即断）
        }
    }

    [Fact]
    public async Task 并发上限占满即拒_释放回收恢复()
    {
        using var idle = new TcpClient(); // 裸 TCP 占位（不发 HTTP——accept 即计入额度）
        await idle.ConnectAsync("127.0.0.1", _http.BaseAddress!.Port);

        // 占满：新 HTTP 连接被断（无应答）。并行负载下 Kestrel 连接计入有毫秒级竞态
        // （占位连接可能尚未计入）——轮询收敛到「被拒」稳定态而非单次判定
        bool refused = false;
        for (var i = 0; i < 30 && !refused; i++)
        {
            if (await GetStatusAsync(1000) is null) refused = true;
            else await Task.Delay(100); // 401=占位尚未计入：稍候重试
        }
        Assert.True(refused, "占位连接计入额度后新连接应被拒");

        idle.Close(); // 对端断开 → 额度回收
        HttpStatusCode? recovered = null;
        for (var i = 0; i < 50 && recovered is null; i++) // 回收竞态：轮询收敛
        {
            await Task.Delay(100);
            recovered = await GetStatusAsync();
        }
        Assert.Equal(HttpStatusCode.Unauthorized, recovered); // 恢复可达（401=连接可建+宿主存活）
    }
}
