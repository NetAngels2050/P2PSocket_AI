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
/// M3-08 系统配置与审计日志 API（FR-S-825、NFR-54、04 §3.2）：GET 白名单全集现值+重启标注；
/// PUT 合法值写库+审计+relay_rate_limit 进程桶即时联动（M3-07 同执行链）+log_level 规范形态；
/// 非法值/白名单外键 400 {1001} 且不动库值；审计 newest-first 分页+事件过滤。
/// 最小夹具（无 ControlServer——两 API 均纯 DB/Web 面）。
/// </summary>
public sealed class AdminSystemApiTests : IAsyncLifetime
{
    private readonly TestDatabase _db = new();
    private readonly DeviceRegistry _registry = new();
    private ServerWebHostService _web = null!;
    private HttpClient _http = null!;
    private RelayRateLimiter _limiter = null!;
    private LoginThrottle _throttle = null!;
    private IDbContextFactory<AppDbContext> _factory = null!;

    public async Task InitializeAsync()
    {
        _factory = new StubFactory(CreateDb);
        using (var init = _factory.CreateDbContext())
            DbInitializer.Initialize(init);

        var audit = new AuditLogger(_factory);
        _limiter = new RelayRateLimiter(0);
        var invalidation = new InvalidationPusher(_factory, _registry);
        var pusher = new DeviceListPusher(_factory, _registry);
        var groupService = new GroupService(_factory, _registry, audit, pusher, invalidation);
        var admin = new AdminService(_factory, _registry, audit, invalidation, listPusher: pusher);

        var options = new ServerOptions { Listen = { Web = 0 } }; // 0=OS 分配：启动后 _web.BoundPort 回读（并行夹具零撞口）
        _throttle = new LoginThrottle(); // M5-04：PUT 热更联动件（System 时钟——本夹具无假时钟推进需求）
        _web = new ServerWebHostService(options, TimeProvider.System, new AdminSessionStore(TimeProvider.System),
            _factory, audit, admin, _registry, groupService, null, null, _limiter,
            loginThrottle: _throttle)
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
        _db.Dispose();
    }

    private AppDbContext CreateDb() => new(
        new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_db.DataSource).Options);

    private async Task<JsonElement> GetAsync(string url)
        => JsonSerializer.Deserialize<JsonElement>(
            await (await _http.GetAsync(url)).Content.ReadAsStreamAsync());

    private async Task<(HttpStatusCode Status, JsonElement Body)> PutAsync(object body)
    {
        var resp = await _http.PutAsJsonAsync("/api/system/config", body);
        return (resp.StatusCode,
            JsonSerializer.Deserialize<JsonElement>(await resp.Content.ReadAsStreamAsync()));
    }

    [Fact]
    public async Task GET_白名单全集与重启标注()
    {
        var items = (await GetAsync("/api/system/config")).GetProperty("data").GetProperty("items")
            .EnumerateArray().ToList();
        Assert.Equal(DbInitializer.ConfigDefaults.Length, items.Count); // 白名单=ConfigDefaults 全集
        Assert.Equal(DbInitializer.ConfigDefaults.Select(k => k.Key).Order().ToArray(),
            items.Select(i => i.GetProperty("key").GetString()!).Order().ToArray());

        var byKey = items.ToDictionary(i => i.GetProperty("key").GetString()!);
        Assert.Equal("1", byKey["relay_enabled"].GetProperty("value").GetString()); // 种子现值
        Assert.Equal("0", byKey["relay_rate_limit"].GetProperty("value").GetString());
        Assert.Equal("Information", byKey["log_level"].GetProperty("value").GetString());
        Assert.True(byKey["public_addr"].GetProperty("restartRequired").GetBoolean()); // 启动期读
        Assert.True(byKey["stun_auth"].GetProperty("restartRequired").GetBoolean());
        Assert.True(byKey["log_level"].GetProperty("restartRequired").GetBoolean());
        Assert.False(byKey["relay_enabled"].GetProperty("restartRequired").GetBoolean()); // 运行期现读
        Assert.False(byKey["default_join_policy"].GetProperty("restartRequired").GetBoolean());
        Assert.Equal("1", byKey["device_registration_open"].GetProperty("value").GetString()); // M5-02 种子：默认开放
        Assert.False(byKey["device_registration_open"].GetProperty("restartRequired").GetBoolean()); // 注册路径现读
        Assert.True(byKey["register_rate_per_ip"].GetProperty("restartRequired").GetBoolean()); // 启动期入令牌桶
        Assert.Equal("900", byKey["login_fail_window_sec"].GetProperty("value").GetString()); // M5-04 种子
        Assert.Equal("8000", byKey["login_delay_cap_ms"].GetProperty("value").GetString());
        Assert.False(byKey["login_fail_window_sec"].GetProperty("restartRequired").GetBoolean()); // PUT 热更联动
        Assert.False(byKey["login_delay_cap_ms"].GetProperty("restartRequired").GetBoolean());
        // M5-07 告警七键种子（OQ-21③ 默认关；AlertPusher 每 tick 现读——皆即时生效）
        Assert.Equal("0", byKey["alert_enabled"].GetProperty("value").GetString());
        Assert.Equal("", byKey["alert_webhook_url"].GetProperty("value").GetString());
        Assert.Equal("300", byKey["alert_window_sec"].GetProperty("value").GetString());
        Assert.Equal("1800", byKey["alert_silence_sec"].GetProperty("value").GetString());
        Assert.Equal("10", byKey["alert_login_fail_count"].GetProperty("value").GetString());
        Assert.Equal("5", byKey["alert_register_count"].GetProperty("value").GetString());
        Assert.Equal("200", byKey["alert_stun_drop_count"].GetProperty("value").GetString());
        Assert.False(byKey["alert_enabled"].GetProperty("restartRequired").GetBoolean());
        Assert.False(byKey["alert_webhook_url"].GetProperty("restartRequired").GetBoolean());
        Assert.Equal("1", byKey["autoban_enabled"].GetProperty("value").GetString()); // M5-08 缺省开
        Assert.Equal("600", byKey["autoban_window_sec"].GetProperty("value").GetString());
        Assert.Equal("20", byKey["autoban_fail_count"].GetProperty("value").GetString());
        Assert.Equal("3600", byKey["autoban_duration_sec"].GetProperty("value").GetString());
        Assert.False(byKey["autoban_enabled"].GetProperty("restartRequired").GetBoolean()); // tick 现读
        // M5-10/SEC-64 监听面资源上限四键（07 §12）：前三 accept/JOIN 现读即时生效；
        // web_max_connections 启动期入 Kestrel——RestartKeys 同标
        Assert.Equal("64", byKey["control_conn_max_per_ip"].GetProperty("value").GetString());
        Assert.Equal("1024", byKey["control_conn_max_total"].GetProperty("value").GetString());
        Assert.Equal("30", byKey["relay_join_rate_per_ip"].GetProperty("value").GetString());
        Assert.Equal("64", byKey["web_max_connections"].GetProperty("value").GetString());
        Assert.False(byKey["control_conn_max_per_ip"].GetProperty("restartRequired").GetBoolean());
        Assert.False(byKey["control_conn_max_total"].GetProperty("restartRequired").GetBoolean());
        Assert.False(byKey["relay_join_rate_per_ip"].GetProperty("restartRequired").GetBoolean());
        Assert.True(byKey["web_max_connections"].GetProperty("restartRequired").GetBoolean()); // Kestrel 启动期
        // M5-14/SEC-84 升级链路：产物哈希清单键（种子空=未录入；0x03 现读即时生效）
        Assert.Equal("", byKey["update_artifact_sha256"].GetProperty("value").GetString());
        Assert.False(byKey["update_artifact_sha256"].GetProperty("restartRequired").GetBoolean());
    }

    [Fact]
    public async Task PUT_写库审计与限速联动()
    {
        var (status, body) = await PutAsync(new Dictionary<string, string>
        {
            ["log_level"] = "debug", // 小写→规范形态 Debug
            ["relay_rate_limit"] = "4096",
            ["update_notes"] = "维护窗口提示",
        });
        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Equal(0, body.GetProperty("code").GetInt32());
        var items = body.GetProperty("data").GetProperty("items").EnumerateArray()
            .ToDictionary(i => i.GetProperty("key").GetString()!);
        Assert.Equal("Debug", items["log_level"].GetProperty("value").GetString()); // 回读规范形态
        Assert.Equal("4096", items["relay_rate_limit"].GetProperty("value").GetString());
        Assert.Equal("维护窗口提示", items["update_notes"].GetProperty("value").GetString());
        Assert.Equal(4096, _limiter.RateBytesPerSec); // 进程桶即时联动（M3-07 同执行链）

        await using (var db = CreateDb())
        {
            var cfg = db.ServerConfig.AsNoTracking().ToDictionary(c => c.Key, c => c.Value);
            Assert.Equal("Debug", cfg["log_level"]); // 持久化
            Assert.Equal("4096", cfg["relay_rate_limit"]);
            Assert.Contains(db.AuditLogs.AsNoTracking(),
                l => l.Event == "system_config_change" && l.Detail!.Contains("relay_rate_limit"));
        }
    }

    [Fact]
    public async Task PUT_登录防爆破键_热更LoginThrottle即时生效()
    {
        // 预置两失败（1000ms 档）→ PUT 收帽 500 → 现值档立即被钳制（运行期热更，07 §11）
        _throttle.RecordFailure(LoginThrottle.DimAccount, "probe-user");
        _throttle.RecordFailure(LoginThrottle.DimAccount, "probe-user");
        Assert.Equal(1000, _throttle.LoginDelayMs("probe-user", null));

        var (status, body) = await PutAsync(new Dictionary<string, string>
        {
            ["login_delay_cap_ms"] = "500",
        });
        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Equal(500, _throttle.LoginDelayMs("probe-user", null));

        // 持久化 + 变更入审计（单键 PUT 亦按对热更——另一键取库内现值）
        await using (var db = CreateDb())
        {
            Assert.Equal("500", (await db.ServerConfig.AsNoTracking()
                .SingleAsync(c => c.Key == "login_delay_cap_ms")).Value);
            Assert.Contains(await db.AuditLogs.AsNoTracking().ToListAsync(),
                l => l.Event == "system_config_change" && l.Detail!.Contains("login_delay_cap_ms"));
        }
    }

    [Fact]
    public async Task PUT_非法值_400矩阵()
    {
        var cases = new Dictionary<string, string>
        {
            ["log_level"] = "Verbose2",                    // 枚举外
            ["virtual_subnet"] = "300.1.1.1/24",           // 坏 CIDR
            ["public_addr"] = "http://x",                  // 非法（含 scheme）
            ["max_devices"] = "0",                         // 数值下界
            ["stun_rate_per_ip"] = "-1",                   // 负数
            ["relay_enabled"] = "2",                       // 非 0|1
            ["device_registration_open"] = "on",           // M5-02 非 0|1
            ["register_rate_per_ip"] = "0",                // M5-02 频控下界
            ["login_fail_window_sec"] = "30",              // M5-04 滑动窗下界（60s）
            ["login_delay_cap_ms"] = "70000",              // M5-04 延迟帽上界（60s）
            ["alert_enabled"] = "yes",                     // M5-07 非 0|1
            ["alert_webhook_url"] = "ftp://x",             // M5-07 非 http(s)
            ["alert_window_sec"] = "30",                   // M5-07 窗口下界（60s）
            ["alert_silence_sec"] = "-1",                  // M5-07 静默负值
            ["alert_login_fail_count"] = "0",              // M5-07 阈值下界
            ["autoban_enabled"] = "yes",                   // M5-08 非 0|1
            ["autoban_window_sec"] = "30",                 // M5-08 窗口下界（60s）
            ["autoban_duration_sec"] = "86401",            // M5-08 时长上界（86400s）
            ["control_conn_max_per_ip"] = "0",             // M5-10 并发下界（1）
            ["relay_join_rate_per_ip"] = "0",              // M5-10 速率下界（1）
            ["web_max_connections"] = "abc",               // M5-10 非整数
            ["default_join_policy"] = "open",              // 域外
            ["relay_rate_limit"] = "99999999999",          // 超 int
            ["update_url"] = "http://x",                   // M5-14/SEC-84：http 拒收（强制 https）
            ["update_artifact_sha256"] = "not-json",       // M5-14：非 JSON
        };
        foreach (var (key, value) in cases)
        {
            var (status, body) = await PutAsync(new Dictionary<string, string> { [key] = value });
            Assert.Equal(HttpStatusCode.BadRequest, status);
            Assert.Equal(1001, body.GetProperty("code").GetInt32());
            Assert.Contains(key, body.GetProperty("message").GetString());
        }

        // 拒绝路径不动库值
        await using (var db = CreateDb())
        {
            var cfg = db.ServerConfig.AsNoTracking().ToDictionary(c => c.Key, c => c.Value);
            Assert.Equal("Information", cfg["log_level"]);
            Assert.Equal("0", cfg["relay_rate_limit"]);
            Assert.Equal("100.64.0.0/24", cfg["virtual_subnet"]);
        }
        Assert.Equal(0, _limiter.RateBytesPerSec); // 桶未被动
    }

    [Fact]
    public async Task PUT_告警键_合法值写库持久化()
    {
        var (status, body) = await PutAsync(new Dictionary<string, string>
        {
            ["alert_enabled"] = "1",
            ["alert_webhook_url"] = "http://192.168.1.10:8080/hook",
            ["alert_login_fail_count"] = "20",
            ["autoban_fail_count"] = "30", // M5-08：同款库值持久（tick 现读生效）
            ["control_conn_max_total"] = "2048", // M5-10：accept 现读即时生效
        });
        Assert.Equal(HttpStatusCode.OK, status);
        var items = body.GetProperty("data").GetProperty("items").EnumerateArray()
            .ToDictionary(i => i.GetProperty("key").GetString()!);
        Assert.Equal("1", items["alert_enabled"].GetProperty("value").GetString());
        Assert.Equal("20", items["alert_login_fail_count"].GetProperty("value").GetString());
        Assert.Equal("30", items["autoban_fail_count"].GetProperty("value").GetString());
        Assert.Equal("2048", items["control_conn_max_total"].GetProperty("value").GetString());

        await using var db = CreateDb();
        var cfg = db.ServerConfig.AsNoTracking().ToDictionary(c => c.Key, c => c.Value);
        Assert.Equal("1", cfg["alert_enabled"]); // 持久化（AlertPusher 下 tick 现读生效）
        Assert.Equal("http://192.168.1.10:8080/hook", cfg["alert_webhook_url"]);
        Assert.Equal("30", cfg["autoban_fail_count"]);
    }

    // ── M5-14（SEC-84、07 §14.4）：update_url 强制 https + 产物哈希键形状 ──

    [Fact]
    public async Task PUT_update_url_强制https_http拒收_https放行()
    {
        // http 一律拒收（含大小写混写/非 http(s) 家族）——存量值由 0x03 运行时屏蔽兜底
        foreach (var bad in new[] { "http://example.com/dl", "HTTP://example.com/dl", "ftp://x" })
        {
            var (status, _) = await PutAsync(new Dictionary<string, string> { ["update_url"] = bad });
            Assert.Equal(HttpStatusCode.BadRequest, status);
        }
        await using (var db = CreateDb())
            Assert.Equal("", db.ServerConfig.AsNoTracking().Single(c => c.Key == "update_url").Value); // 拒收不动库

        var (ok, body) = await PutAsync(new Dictionary<string, string> { ["update_url"] = "https://example.com/dl" });
        Assert.Equal(HttpStatusCode.OK, ok);
        Assert.Equal("https://example.com/dl",
            body.GetProperty("data").GetProperty("items").EnumerateArray()
                .Single(i => i.GetProperty("key").GetString() == "update_url").GetProperty("value").GetString());
        await using (var db = CreateDb())
            Assert.Equal("https://example.com/dl",
                db.ServerConfig.AsNoTracking().Single(c => c.Key == "update_url").Value);
    }

    [Fact]
    public async Task PUT_产物哈希键_形状校验与合法写入()
    {
        // 非法形状：JSON 数组/未知产物名/大写 hex/短 hex/值非字符串
        var bad = new[]
        {
            """["windows-setup"]""",                                                        // 数组非对象
            """{"win-setup":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}""", // 产物名域外
            """{"windows-setup":"E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"}""", // 大写拒收
            """{"windows-setup":"e3b0"}""",                                                  // 非 hex64
            """{"windows-setup":123}""",                                                     // 值非字符串
        };
        foreach (var value in bad)
        {
            var (status, _) = await PutAsync(new Dictionary<string, string> { ["update_artifact_sha256"] = value });
            Assert.Equal(HttpStatusCode.BadRequest, status);
        }
        await using (var db = CreateDb())
            Assert.Equal("", db.ServerConfig.AsNoTracking().Single(c => c.Key == "update_artifact_sha256").Value);

        // 合法：三产物名全集（子集亦合法）；持久化后 0x03 原样下发（透传见 UpdateInfoTests）
        const string json =
            """{"windows-setup":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","linux-tar":"a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90","server-tar":"0000000000000000000000000000000000000000000000000000000000000000"}""";
        var (ok, _) = await PutAsync(new Dictionary<string, string> { ["update_artifact_sha256"] = json });
        Assert.Equal(HttpStatusCode.OK, ok);
        await using (var db = CreateDb())
            Assert.Equal(json, db.ServerConfig.AsNoTracking().Single(c => c.Key == "update_artifact_sha256").Value);
    }

    [Fact]
    public async Task PUT_白名单外键_整单拒绝()
    {
        var (status, body) = await PutAsync(new Dictionary<string, string> { ["not_a_key"] = "1" });
        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal(1001, body.GetProperty("code").GetInt32());
        Assert.Contains("白名单", body.GetProperty("message").GetString());

        // 混入合法键亦整单拒绝（全量校验先行——不留半更新）
        (status, _) = await PutAsync(new Dictionary<string, string>
        {
            ["log_level"] = "Debug",
            ["listen.web"] = "7501", // 进程级端口键在 appsettings 不属本端（08 §5.1 分工）
        });
        Assert.Equal(HttpStatusCode.BadRequest, status);
        await using (var db = CreateDb())
            Assert.Equal("Information", db.ServerConfig.AsNoTracking()
                .Single(c => c.Key == "log_level").Value);
    }

    [Fact]
    public async Task 审计_分页与事件过滤()
    {
        var audit = new AuditLogger(_factory);
        for (var i = 0; i < 5; i++)
            await audit.WriteAsync("e1", deviceId: Guid.NewGuid(), detail: new { seq = i });
        for (var i = 0; i < 3; i++)
            await audit.WriteAsync("e2", detail: new { seq = i });

        var data = (await GetAsync("/api/audit-logs")).GetProperty("data");
        Assert.Equal(9, data.GetProperty("total").GetInt32()); // 1 admin_login（夹具）+5 e1+3 e2
        var ids = data.GetProperty("items").EnumerateArray().Select(i => i.GetProperty("id").GetInt64()).ToList();
        Assert.Equal(ids.OrderByDescending(x => x), ids); // newest-first（Id 降序）
        Assert.NotNull(data.GetProperty("items").EnumerateArray().First().GetProperty("detail").GetString());

        var filtered = (await GetAsync("/api/audit-logs?event=e1")).GetProperty("data");
        Assert.Equal(5, filtered.GetProperty("total").GetInt32());
        Assert.All(filtered.GetProperty("items").EnumerateArray(),
            i => Assert.Equal("e1", i.GetProperty("event").GetString()));

        var page2 = (await GetAsync("/api/audit-logs?event=e1&page=2&pageSize=3")).GetProperty("data");
        Assert.Equal(5, page2.GetProperty("total").GetInt32()); // total 不随页变
        Assert.Equal(2, page2.GetProperty("items").EnumerateArray().Count()); // 尾页余量
        Assert.Equal(2, page2.GetProperty("page").GetInt32());
    }
}
