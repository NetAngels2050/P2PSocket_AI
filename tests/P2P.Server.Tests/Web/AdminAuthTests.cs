using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Time.Testing;
using P2P.Server.Data;
using P2P.Server.Services;
using P2P.Server.Web;
using Xunit;

namespace P2P.Server.Tests.Web;

/// <summary>
/// M3-02 管理员会话与账号（FR-S-203、04 §3.1、07 §8、OQ-3）：
/// admin/admin 首登 mustChangePassword / 改密后消失 / 错误密码 401+审计 / logout 失效 Cookie /
/// 旧密码校验 / 会话 8h 过期（假时钟）/ M5-04 限速双维递增（账户维成功复位、IP 维滑窗衰减）。
/// </summary>
public sealed class AdminAuthTests : IAsyncLifetime
{
    private readonly TestDatabase _db = new();
    private readonly FakeTimeProvider _time = new();
    private ServerWebHostService _web = null!;
    private int _port;

    public async Task InitializeAsync()
    {
        var factory = new StubFactory(() => new AppDbContext(
            new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_db.DataSource).Options));
        using (var init = factory.CreateDbContext())
            DbInitializer.Initialize(init); // 种 admin/admin（OQ-3）
        var options = new ServerOptions
        {
            Listen = { Web = Random.Shared.Next(21000, 24000) }, // 测试带（与客户端测试带不相交）
        };
        var registry = new DeviceRegistry(); // 本任务无在线设备（纯账号链）
        _web = new ServerWebHostService(options, _time, new AdminSessionStore(_time), factory,
            new AuditLogger(factory, _time), new AdminService(factory, registry, new AuditLogger(factory)), registry,
            new GroupService(factory, registry, new AuditLogger(factory)),
            loginThrottle: new LoginThrottle(time: _time)) // M5-04：防爆破与 0x21 同组件（07 §11）
        {
            WebRootOverride = Path.Combine(Path.GetTempPath(), $"p2p-no-webroot-{Guid.NewGuid():N}"),
        };
        await _web.StartAsync(CancellationToken.None);
        _port = options.Listen.Web;
    }

    public async Task DisposeAsync()
    {
        await _web.StopAsync(CancellationToken.None);
        _db.Dispose();
    }

    /// <summary>带 Cookie 容器的客户端（login→logout 全链自动携带）。</summary>
    private HttpClient CreateClient()
        => new(new HttpClientHandler { CookieContainer = new CookieContainer() })
        {
            BaseAddress = new Uri($"http://127.0.0.1:{_port}/"),
        };

    private static JsonElement Data(JsonElement body) => body.GetProperty("data");

    private async Task<JsonElement> LoginAsync(HttpClient http, string username, string password)
    {
        var resp = await http.PostAsJsonAsync("/api/auth/login", new { username, password });
        return JsonSerializer.Deserialize<JsonElement>(await resp.Content.ReadAsStreamAsync());
    }

    private async Task<int> AuditCountAsync(string @event)
    {
        await using var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_db.DataSource).Options);
        return await db.AuditLogs.AsNoTracking().CountAsync(a => a.Event == @event);
    }

    /// <summary>阶梯延迟期间的调用（M5-04：FakeTimeProvider 50ms 步进推进放行——轮询防服务端
    /// 未入延迟的竞态；推进即完成 Task.Delay(timeProvider) 等待）。</summary>
    private async Task<T> AdvanceUntilDoneAsync<T>(Func<Task<T>> call)
    {
        var task = call();
        for (var i = 0; i < 400 && !task.IsCompleted; i++)
        {
            _time.Advance(TimeSpan.FromMilliseconds(50));
            await Task.Delay(2);
        }
        return await task;
    }

    private Task<JsonElement> LoginWithAdvanceAsync(HttpClient http, string username, string password)
        => AdvanceUntilDoneAsync(() => LoginAsync(http, username, password));

    /// <summary>改密请求（M5-05 起校验前吃阶梯延迟——统一经假时钟推进放行后取 body）。</summary>
    private Task<JsonElement> ChangePasswordAsync(HttpClient http, string oldPassword, string newPassword)
        => AdvanceUntilDoneAsync(async () =>
        {
            var resp = await http.PostAsJsonAsync("/api/auth/change-password", new { oldPassword, newPassword });
            return JsonSerializer.Deserialize<JsonElement>(await resp.Content.ReadAsStreamAsync());
        });

    // ── FR-S-203 主链 ────────────────────────────────────────────────────

    [Fact]
    public async Task 首登admin默认口令_必须改密提示_审计与Cookie属性()
    {
        using var http = CreateClient();
        var resp = await http.PostAsJsonAsync("/api/auth/login", new { username = "admin", password = "admin" });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var body = JsonSerializer.Deserialize<JsonElement>(await resp.Content.ReadAsStreamAsync());
        Assert.Equal(0, body.GetProperty("code").GetInt32());
        Assert.True(Data(body).GetProperty("mustChangePassword").GetBoolean());

        // Cookie：HttpOnly、SameSite=Strict、无 Secure（HTTP，D11）——已由容器收下；属性断言走原始头
        var setCookie = Assert.Single(resp.Headers.GetValues("Set-Cookie"));
        Assert.Contains("httponly", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=strict", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("secure", setCookie, StringComparison.OrdinalIgnoreCase);

        // 会话生效：携 Cookie 访问受保护区不再 401；审计 admin_login
        Assert.NotEqual(HttpStatusCode.Unauthorized,
            (await http.GetAsync("/api/dashboard")).StatusCode);
        Assert.Equal(1, await AuditCountAsync("admin_login"));
    }

    [Fact]
    public async Task 错误密码401_审计admin_login_fail_无会话Cookie()
    {
        using var http = CreateClient();
        var resp = await http.PostAsJsonAsync("/api/auth/login", new { username = "admin", password = "wrong!" });
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        var body = JsonSerializer.Deserialize<JsonElement>(await resp.Content.ReadAsStreamAsync());
        Assert.Equal(2001, body.GetProperty("code").GetInt32());

        Assert.False(resp.Headers.Contains("Set-Cookie")); // 失败不发会话
        Assert.Equal(1, await AuditCountAsync("admin_login_fail"));
        // 非管理员用户名同拒（单管理员 D16）——同 IP 第 2 次失败已上 500ms 档（M5-04），假时钟推进放行
        var second = await LoginWithAdvanceAsync(http, "nobody", "x");
        Assert.Equal(2001, second.GetProperty("code").GetInt32());
    }

    [Fact]
    public async Task 改密全链_旧密码校验_改后提示消失_旧口令失效()
    {
        using var http = CreateClient();
        Assert.Equal(HttpStatusCode.OK,
            (await http.PostAsJsonAsync("/api/auth/login", new { username = "admin", password = "admin" })).StatusCode);

        // 未登录不可改密（认证中间件 401）——换无 Cookie 客户端验证
        using var bare = new HttpClient { BaseAddress = http.BaseAddress };
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await bare.PostAsJsonAsync("/api/auth/change-password", new { oldPassword = "admin", newPassword = "abcdef" })).StatusCode);

        // 旧密码错 → 401（首败零延迟即时）；新密码 <6 → 400（参数校验先于延迟）
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await http.PostAsJsonAsync("/api/auth/change-password", new { oldPassword = "bad", newPassword = "abcdef" })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest,
            (await http.PostAsJsonAsync("/api/auth/change-password", new { oldPassword = "admin", newPassword = "123" })).StatusCode);

        // 成功改密（M5-05 后 IP 维 1 败吃 500ms 档——推进放行）→ 审计；mustChangePassword 消失、旧口令失效
        Assert.Equal(0, (await ChangePasswordAsync(http, "admin", "newpass6")).GetProperty("code").GetInt32());
        Assert.Equal(1, await AuditCountAsync("admin_change_password"));

        using var re = CreateClient();
        var again = await LoginWithAdvanceAsync(re, "admin", "newpass6"); // IP 维不清零仍吃档
        Assert.False(Data(again).GetProperty("mustChangePassword").GetBoolean());
        Assert.Equal(2001, (await LoginWithAdvanceAsync(re, "admin", "admin")).GetProperty("code").GetInt32());
    }

    [Fact]
    public async Task 改密防爆破_错旧密码延迟递增_成功复位账户维()
    {
        using var http = CreateClient();
        Assert.Equal(0, (await LoginAsync(http, "admin", "admin")).GetProperty("code").GetInt32());

        // 首败零延迟即时 401；第 2 次错旧密码吃 500ms 档（双维各 1 败）
        Assert.Equal(2001, (await ChangePasswordAsync(http, "bad-1", "abcdef9")).GetProperty("code").GetInt32());
        Assert.Equal(2001, (await ChangePasswordAsync(http, "bad-2", "abcdef9")).GetProperty("code").GetInt32());

        // 第 3 次正确旧密码：吃 1000ms 档仍成功——账户维复位（IP 维不清零）
        Assert.Equal(0, (await ChangePasswordAsync(http, "admin", "newpass7")).GetProperty("code").GetInt32());

        // 新口令下再改：账户维已清零、IP 维 2 败仍在 → 仍吃 1000ms 档后成功
        Assert.Equal(0, (await ChangePasswordAsync(http, "newpass7", "newpass8")).GetProperty("code").GetInt32());

        // 阶跃审计：acct/ip 两维各 fails=1,2 → 4 条（与 login 同键共享）；改密成功审计 2 次
        Assert.Equal(4, await AuditCountAsync("login_throttled"));
        Assert.Equal(2, await AuditCountAsync("admin_change_password"));
    }

    [Fact]
    public async Task logout后Cookie失效_受保护区回落401()
    {
        using var http = CreateClient();
        Assert.Equal(HttpStatusCode.OK,
            (await http.PostAsJsonAsync("/api/auth/login", new { username = "admin", password = "admin" })).StatusCode);
        Assert.NotEqual(HttpStatusCode.Unauthorized, (await http.GetAsync("/api/dashboard")).StatusCode);

        Assert.Equal(HttpStatusCode.OK, (await http.PostAsync("/api/auth/logout", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await http.GetAsync("/api/dashboard")).StatusCode); // 会话已删
    }

    [Fact]
    public async Task 会话8小时过期_假时钟推进后失效()
    {
        using var http = CreateClient();
        Assert.Equal(HttpStatusCode.OK,
            (await http.PostAsJsonAsync("/api/auth/login", new { username = "admin", password = "admin" })).StatusCode);
        _time.Advance(TimeSpan.FromHours(8).Add(TimeSpan.FromMinutes(1)));
        Assert.Equal(HttpStatusCode.Unauthorized, (await http.GetAsync("/api/dashboard")).StatusCode);
    }

    [Fact]
    public async Task 限速双维递增_账户维成功复位_IP维滑窗衰减()
    {
        using var http = CreateClient();
        // 第 1 次失败无延迟即时应答；第 2 次失败双维各上 500ms 档（假时钟推进放行）
        var fail1 = await LoginAsync(http, "admin", "bad-1");
        Assert.Equal(2001, fail1.GetProperty("code").GetInt32());
        var fail2 = await LoginWithAdvanceAsync(http, "admin", "bad-2");
        Assert.Equal(2001, fail2.GetProperty("code").GetInt32());

        // 第 3 次正确口令：先吃 1000ms 当前档（A-15 延迟期间正确登录同受档）仍成功——账户维复位
        var ok = await LoginWithAdvanceAsync(http, "admin", "admin");
        Assert.Equal(0, ok.GetProperty("code").GetInt32());

        // 第 4 次正确口令：IP 维仍有 2 次窗内计数（成功不清 IP 维，07 §11.1 防穿插复位）→ 仍吃 1000ms 档
        var ok2 = await LoginWithAdvanceAsync(http, "admin", "admin");
        Assert.Equal(0, ok2.GetProperty("code").GetInt32());

        // 窗口自然衰减：推进 901s > 900s 窗 → 双维归零，登录无延迟即时完成（不推进即回=零感知）
        _time.Advance(TimeSpan.FromSeconds(901));
        var noDelay = await LoginAsync(http, "admin", "admin");
        Assert.Equal(0, noDelay.GetProperty("code").GetInt32());

        Assert.Equal(2, await AuditCountAsync("admin_login_fail")); // 仅两次失败
        // 阶跃审计（07 §11.3）：account/ip 两维各在 fails=1,2 跨档 → 各 2 条共 4 条
        Assert.Equal(4, await AuditCountAsync("login_throttled"));
    }
}
