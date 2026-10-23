using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using P2P.Client.Control;
using P2P.Client.Hosting;
using P2P.Client.Storage;
using P2P.Core.Crypto;
using P2P.Core.Protocol;
using P2P.Nic;
using P2P.Server.Data;
using P2P.Server.Services;
using Xunit;

namespace P2P.IntegrationTests;

/// <summary>
/// M1-30 客户端宿主集成测试（任务清单完成判定的代码层等价：kill 后系统拉起且状态恢复——
/// 映射/网卡/通道三要素经同一 baseDir 重启重建；实机服务安装冒烟属 M1-37）。
/// 虚拟 IP 用 127.0.0.1 模拟（M1-35 同法：监听可绑定、隔离语义等价）；网卡用替身记录。
/// 全运行时重组件专用集合（与 ScenarioIntegrationTests 共用，避免并行叠加满载偶发）。
/// </summary>
[Collection("heavy-runtime")]
public sealed class ClientRuntimeIntegrationTests : IAsyncLifetime
{
    private readonly TestDatabase _db = new();
    private readonly DeviceRegistry _registry = new();
    private readonly List<SignalingCoordinator> _signalings = [];
    private readonly List<RelayService> _relays = [];
    private readonly List<ControlServer> _servers = [];
    private readonly StubNicManager _nic = new();
    private StubFactory _factory = null!;
    private string _rootDir = null!;
    private int _port;

    public async Task InitializeAsync()
    {
        _factory = new StubFactory(CreateDb);
        using (var init = _factory.CreateDbContext())
            DbInitializer.Initialize(init);
        var server = await StartServerAsync(0);
        _port = server.LocalEndPoint!.Port;
        _rootDir = Path.Combine(Path.GetTempPath(), $"p2p-it-rt-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_rootDir);
    }

    public async Task DisposeAsync()
    {
        foreach (var s in _servers) await s.DisposeAsync();
        foreach (var r in _relays) await r.DisposeAsync();
        foreach (var s in _signalings) await s.DisposeAsync();
        await Task.Delay(200); // 服务端收尾与夹具销毁竞态宽限（LocalWebApi 测试同法）
        try { _db.Dispose(); }
        catch (InvalidOperationException) { }
        try { Directory.Delete(_rootDir, true); } catch (IOException) { }
    }

    private AppDbContext CreateDb() => new(
        new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_db.DataSource).Options);

    private async Task<ControlServer> StartServerAsync(int port)
    {
        var audit = new AuditLogger(_factory);
        var signaling = new SignalingCoordinator(_factory, _registry, new Authorizer(_factory), audit);
        var relay = new RelayService(_factory, _registry, signaling.ResolveRelayPeers);
        var router = new ControlMessageRouter(
            new RegistrationService(_factory, _registry, audit),
            new UserService(_factory, audit),
            new GroupService(_factory, _registry, audit),
            signaling,
            new MappingService(_factory, audit),
            relay,
            new StatsService(_factory, audit),
            audit);
        var server = new ControlServer(_factory, _registry, router.DispatchAsync);
        await server.StartAsync(new IPEndPoint(IPAddress.Loopback, port));
        _signalings.Add(signaling);
        _relays.Add(relay);
        _servers.Add(server);
        return server;
    }

    private static int FreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    private sealed record SeededDevice(Guid DeviceId, byte[] DeviceSecret, string RemoteCode);

    /// <summary>种已注册设备 + 服务端映射行（Enabled=true）+ A/B 共同分组（重启后无登录态仍 L2 可见；
    /// createSharedGroup=false：无分组变体——可见性仅剩"同账号设备"路径，登录前目标不可见（P3 用例））。</summary>
    private async Task<SeededDevice> SeedRegisteredWithMappingAsync(string name, SeededDevice? peer,
        bool createSharedGroup = true)
    {
        await using var db = _factory.CreateDbContext();
        var secret = RandomGenerator.Bytes(32);
        var device = new Device
        {
            Id = Guid.NewGuid(),
            DeviceName = name,
            Os = "windows",
            ClientVersion = "0.1.0",
            MacCode = $"IT-{Guid.NewGuid():N}"[..16],
            RemoteCode = FakeRemoteCode(),
            VirtualIp = "127.0.0.1", // 测试模拟（M1-35 口径）：监听可绑定，隔离语义等价
            StaticPubKey = new byte[65],
            DeviceSecret = secret,
            OwnerUserId = null,
            LastSeenAt = DateTime.UtcNow,
            CreatedAt = DateTime.UtcNow,
        };
        db.Devices.Add(device);

        ushort localPort = 0;
        if (peer is not null)
        {
            localPort = (ushort)FreePort();
            db.Mappings.Add(new Mapping
            {
                Id = Guid.NewGuid(),
                OwnerDeviceId = device.Id,
                Name = "restore",
                LocalPort = localPort,
                Proto = "tcp",
                TargetDeviceId = peer.DeviceId,
                TargetAddr = "self",
                TargetPort = 80,
                Enabled = true,
                CreatedAt = DateTime.UtcNow,
            });
            // 共同分组（无登录态路径的 L2 可见性；owner=内置 admin，外键要求真实用户）
            if (createSharedGroup)
            {
                var group = new Group
                {
                    Id = Guid.NewGuid(),
                    Name = $"rt-{Guid.NewGuid():N}"[..16],
                    OwnerUserId = db.Users.Single(u => u.IsAdmin).Id,
                    IsDefault = false,
                    JoinPolicy = "free",
                    CreatedAt = DateTime.UtcNow,
                };
                db.Groups.Add(group);
                db.GroupMembers.Add(new GroupMember { Id = Guid.NewGuid(), GroupId = group.Id, DeviceId = device.Id, Approved = true });
                db.GroupMembers.Add(new GroupMember { Id = Guid.NewGuid(), GroupId = group.Id, DeviceId = peer.DeviceId, Approved = true });
            }
        }
        await db.SaveChangesAsync();

        // 客户端侧 state.json：三要素 + 启用中映射（与服务端行同口径）
        var dir = Path.Combine(_rootDir, name);
        Directory.CreateDirectory(dir);
        var store = new StateStore(dir);
        store.State.DeviceId = device.Id;
        store.State.DeviceSecret = secret;
        store.State.StaticPrivateKey = EcKeyPair.Generate().ExportPrivateKey();
        store.State.RemoteCode = device.RemoteCode;
        store.State.VirtualIp = device.VirtualIp;
        if (peer is not null)
            store.State.Mappings.Add(new StoredMapping(
                db.Mappings.AsNoTracking().Single(m => m.OwnerDeviceId == device.Id).Id, "restore",
                localPort, "tcp", peer.RemoteCode, "self", 80, Enabled: true));
        await store.SaveAsync();
        var settings = new SettingsStore(dir);
        await settings.SaveAsync(new ClientSettings
        {
            ServerAddrs = [$"127.0.0.1:{_port}"],
            LocalWebPort = FreePort(),
        });
        return new SeededDevice(device.Id, secret, device.RemoteCode);
    }

    private static string FakeRemoteCode()
    {
        const string alphabet = "0123456789abc";
        return new string(RandomGenerator.Bytes(6).Select(b => alphabet[b % alphabet.Length]).ToArray());
    }

    private static async Task<string> GetPhaseAsync(HttpClient http)
    {
        using var response = await http.GetAsync("/api/system/state");
        var root = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(0, root.GetProperty("code").GetInt32());
        return root.GetProperty("data").GetProperty("phase").GetString()!;
    }

    private static async Task<string>GetMappingStateAsync(HttpClient http)
    {
        using var response = await http.GetAsync("/api/mappings");
        var root = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        var items = root.GetProperty("data").GetProperty("items");
        return items.GetArrayLength() == 0 ? "" : items[0].GetProperty("state").GetString()!;
    }

    /// <summary>本地 Web HTTP 客户端（M5-12，07 §14.2）：注入 Bearer token——裸 HTTP 401。</summary>
    private static HttpClient LocalHttp(ClientRuntime runtime)
    {
        var http = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{runtime.WebPort}") };
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", runtime.WebToken);
        return http;
    }

    // ── ① 重启状态恢复：网卡/通道/映射三要素经同一 baseDir 重建（完成判定）──

    [Fact]
    public async Task 重启后_网卡应用_通道建立_启用映射恢复并打洞()
    {
        var b = await SeedRegisteredWithMappingAsync("rt-b", null);
        var a = await SeedRegisteredWithMappingAsync("rt-a", b);
        var dirA = Path.Combine(_rootDir, "rt-a");

        // 首次启动：registered 路径阻塞至 Established+恢复完成；真实打洞器接线（STUN 不可达 → failed）
        var runtime1 = new ClientRuntime(new ClientRuntimeOptions { BaseDir = dirA, NicOverride = _nic });
        var logs = new List<string>();
        runtime1.Log += logs.Add;
        await runtime1.StartAsync();
        using (var http = LocalHttp(runtime1))
        {
            Assert.Equal("running", await GetPhaseAsync(http));
            Assert.Contains(IPAddress.Loopback, _nic.Ensured); // 网卡已应用（替身记录）
            await WaitStateAsync(http, "failed"); // 真打洞器出队→STUN 探测不可达→failed（确定性）
        }

        // 模拟服务停止 → 系统拉起（同 baseDir；token 随重启轮换——07 §14.2，客户端须随重启重建）
        await runtime1.DisposeAsync();
        var runtime2 = new ClientRuntime(new ClientRuntimeOptions { BaseDir = dirA, NicOverride = _nic });
        await runtime2.StartAsync();
        using (var http = LocalHttp(runtime2))
        {
            Assert.Equal("running", await GetPhaseAsync(http));
            await WaitStateAsync(http, "failed");
            Assert.Equal(2, _nic.Ensured.Count(ip => ip.Equals(IPAddress.Loopback))); // 两次拉起各应用一次
        }
        await runtime2.DisposeAsync();
    }

    // ── ①c M5-12 可配置化（07 §14.2 v1.83，默认关）：出厂免 token 可用；显式开启 → 裸 HTTP 401+带 token 200 ──

    [Fact]
    public async Task 本地Web鉴权开关_默认关免token可用_开启后裸401带token200()
    {
        await SeedRegisteredWithMappingAsync("rt-auth", null);
        var dir = Path.Combine(_rootDir, "rt-auth");

        // 默认（webTokenAuth=false，v1.83）：不带 Bearer 的裸请求直接可用（出厂形态）
        var runtime1 = new ClientRuntime(new ClientRuntimeOptions { BaseDir = dir, NicOverride = _nic });
        await runtime1.StartAsync();
        using (var bare = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{runtime1.WebPort}") })
            Assert.Equal("running", await GetPhaseAsync(bare));
        await runtime1.DisposeAsync();

        // 开启（settings 落盘）→ 重启：裸请求 401+envelope{2001}；带 Bearer 200
        var store = new SettingsStore(dir);
        store.Load();
        var on = store.Settings;
        on.WebTokenAuth = true;
        await store.SaveAsync(on);

        var runtime2 = new ClientRuntime(new ClientRuntimeOptions { BaseDir = dir, NicOverride = _nic });
        await runtime2.StartAsync();
        using (var bare = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{runtime2.WebPort}") })
        using (var denied = await bare.GetAsync("/api/system/state"))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
            var root = JsonDocument.Parse(await denied.Content.ReadAsStringAsync()).RootElement;
            Assert.Equal((int)ErrorCode.Unauthorized, root.GetProperty("code").GetInt32());
        }
        using (var http = LocalHttp(runtime2)) // 带当前 token 的客户端（生产=前端 sessionStorage 注入同构）
            Assert.Equal("running", await GetPhaseAsync(http));
        await runtime2.DisposeAsync();
    }

    private static async Task WaitStateAsync(HttpClient http, string state)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        string current = "";
        while (!cts.IsCancellationRequested)
        {
            current = await GetMappingStateAsync(http);
            if (current == state) return;
            await Task.Delay(200, cts.Token);
        }
        Assert.Fail($"等待映射状态 {state} 超时（当前 {current}）");
    }

    /// <summary>等待日志行出现（后台线程写入，锁保护快照读）。</summary>
    private static async Task WaitLogAsync(List<string> logs, string substring)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        while (!cts.IsCancellationRequested)
        {
            lock (logs) { if (logs.Any(l => l.Contains(substring))) return; }
            await Task.Delay(100, cts.Token);
        }
        Assert.Fail($"等待日志“{substring}”超时");
    }

    // ── ①b P3 修复：无共同分组启动恢复受阻（目标不可见）→ 登录成功自动补恢复 ──

    [Fact]
    public async Task 启动未登录恢复受阻_登录成功后自动补恢复启用映射()
    {
        var b = await SeedRegisteredWithMappingAsync("lr-b", null);
        var a = await SeedRegisteredWithMappingAsync("lr-a", b, createSharedGroup: false);
        var dirA = Path.Combine(_rootDir, "lr-a");

        var runtime = new ClientRuntime(new ClientRuntimeOptions { BaseDir = dirA, NicOverride = _nic });
        var logs = new List<string>();
        runtime.Log += m => { lock (logs) logs.Add(m); };
        await runtime.StartAsync();
        using (var http = LocalHttp(runtime))
        {
            // 启动恢复确定性失败：无登录态且无共同分组 → 0x40 不可见 → 4003（仅日志，映射停留 disabled）
            await WaitLogAsync(logs, "恢复失败（startup）");
            Assert.Equal("disabled", await GetMappingStateAsync(http));

            // 建号（0x20）→ 目标设备绑同账号（可见性前提：本账号设备；外键直改库模拟对端登录过的效果）
            var username = $"u{Guid.NewGuid():N}"[..12];
            using (var reg = await http.PostAsync("/api/auth/register", new StringContent(
                JsonSerializer.Serialize(new { username, password = "secret123" }),
                System.Text.Encoding.UTF8, "application/json")))
            {
                Assert.Equal(0, JsonDocument.Parse(await reg.Content.ReadAsStringAsync())
                    .RootElement.GetProperty("code").GetInt32());
            }
            await using (var db = _factory.CreateDbContext())
            {
                db.Devices.Single(d => d.Id == b.DeviceId).OwnerUserId =
                    db.Users.Single(u => u.Username == username).Id;
                await db.SaveChangesAsync();
            }

            // 登录（0x21）→ LoginSucceeded → 恢复重入：目标可见 → 启用即打洞 → STUN 不可达确定性 failed
            using (var login = await http.PostAsync("/api/auth/login", new StringContent(
                JsonSerializer.Serialize(new { username, password = "secret123" }),
                System.Text.Encoding.UTF8, "application/json")))
            {
                Assert.Equal(0, JsonDocument.Parse(await login.Content.ReadAsStringAsync())
                    .RootElement.GetProperty("code").GetInt32());
            }
            await WaitStateAsync(http, "failed"); // 用例①同口径：真打洞器出队→STUN 探测不可达→failed
            await WaitLogAsync(logs, "登录成功");
        }
        await runtime.DisposeAsync();
    }

    // ── ①c P2 方案 a（2026-10-11 批复）：登录态跨重启保持（凭据记住/自动重放/登出忘记）──

    [Fact]
    public async Task 登录后重启_凭据自动重放_登录态与映射恢复保持_登出即忘记()
    {
        var b = await SeedRegisteredWithMappingAsync("p2-b", null);
        var a = await SeedRegisteredWithMappingAsync("p2-a", b, createSharedGroup: false);
        var dirA = Path.Combine(_rootDir, "p2-a");

        // 第一段：登录（凭据落盘）→ 恢复到位
        var runtime1 = new ClientRuntime(new ClientRuntimeOptions { BaseDir = dirA, NicOverride = _nic });
        var logs1 = new List<string>();
        runtime1.Log += m => { lock (logs1) logs1.Add(m); };
        await runtime1.StartAsync();
        string username;
        using (var http = LocalHttp(runtime1))
        {
            await WaitLogAsync(logs1, "恢复失败（startup）"); // 未登录+无共同分组：确定性受阻（①b 同款前置）
            username = $"u{Guid.NewGuid():N}"[..12];
            using (var reg = await http.PostAsync("/api/auth/register", new StringContent(
                JsonSerializer.Serialize(new { username, password = "secret123" }),
                System.Text.Encoding.UTF8, "application/json")))
            {
                Assert.Equal(0, JsonDocument.Parse(await reg.Content.ReadAsStringAsync())
                    .RootElement.GetProperty("code").GetInt32());
            }
            await using (var db = _factory.CreateDbContext())
            {
                db.Devices.Single(d => d.Id == b.DeviceId).OwnerUserId =
                    db.Users.Single(u => u.Username == username).Id;
                await db.SaveChangesAsync();
            }
            using (var login = await http.PostAsync("/api/auth/login", new StringContent(
                JsonSerializer.Serialize(new { username, password = "secret123" }),
                System.Text.Encoding.UTF8, "application/json")))
            {
                Assert.Equal(0, JsonDocument.Parse(await login.Content.ReadAsStringAsync())
                    .RootElement.GetProperty("code").GetInt32());
            }
            await WaitStateAsync(http, "failed"); // 登录补恢复生效（①b 同口径终态）
        }
        await runtime1.DisposeAsync();
        // 凭据确已落盘（用户名明文字段）
        Assert.Contains(username, await File.ReadAllTextAsync(Path.Combine(dirA, "state.json")));

        // 第二段：重启 → 记住的凭据自动重放 → 登录态+可见性就位 → 映射恢复（无手工登录）
        var runtime2 = new ClientRuntime(new ClientRuntimeOptions { BaseDir = dirA, NicOverride = _nic });
        var logs2 = new List<string>();
        runtime2.Log += m => { lock (logs2) logs2.Add(m); };
        await runtime2.StartAsync();
        using (var http = LocalHttp(runtime2))
        {
            await WaitLogAsync(logs2, $"已自动登录（{username}");
            using var me = await http.GetAsync("/api/auth/me");
            var meRoot = JsonDocument.Parse(await me.Content.ReadAsStringAsync()).RootElement.GetProperty("data");
            Assert.Equal(username, meRoot.GetProperty("username").GetString());
            Assert.Equal("normal", meRoot.GetProperty("mode").GetString());
            await WaitStateAsync(http, "failed"); // 自动登录→LoginSucceeded→补恢复（或 startup 时已可见）→ failed

            // 第三段：登出即忘记（凭据清除）→ 再重启不再自动登录
            using (var logout = await http.PostAsync("/api/auth/logout", null))
            {
                Assert.Equal(0, JsonDocument.Parse(await logout.Content.ReadAsStringAsync())
                    .RootElement.GetProperty("code").GetInt32());
            }
        }
        await runtime2.DisposeAsync();
        var runtime3 = new ClientRuntime(new ClientRuntimeOptions { BaseDir = dirA, NicOverride = _nic });
        var logs3 = new List<string>();
        runtime3.Log += m => { lock (logs3) logs3.Add(m); };
        await runtime3.StartAsync();
        using (var http = LocalHttp(runtime3))
        {
            await WaitLogAsync(logs3, "恢复失败（startup）"); // 无凭据无登录：回到 ①b 受阻形态
            using var me = await http.GetAsync("/api/auth/me");
            var meRoot = JsonDocument.Parse(await me.Content.ReadAsStringAsync()).RootElement.GetProperty("data");
            Assert.Null(meRoot.GetProperty("username").GetString());
            Assert.Equal("disabled", await GetMappingStateAsync(http));
        }
        await runtime3.DisposeAsync();
    }

    // ── ①d 缺陷批次 2 修 A/C/D：运行中断线重连——凭据重放+登录态保持+failed 映射兜底 ──

    [Fact]
    public async Task 登录后断线重连_凭据自动重放_登录态保持_failed映射兜底()
    {
        var b = await SeedRegisteredWithMappingAsync("rc-b", null);
        var a = await SeedRegisteredWithMappingAsync("rc-a", b, createSharedGroup: false);
        var dirA = Path.Combine(_rootDir, "rc-a");

        var runtime = new ClientRuntime(new ClientRuntimeOptions { BaseDir = dirA, NicOverride = _nic });
        var logs = new List<string>();
        runtime.Log += m => { lock (logs) logs.Add(m); };
        await runtime.StartAsync();
        using (var http = LocalHttp(runtime))
        {
            // 前置与 ①b 同款：未登录恢复受阻 → 建号+对端绑同账号 → 登录 → 补恢复 → failed
            await WaitLogAsync(logs, "恢复失败（startup）");
            var username = $"u{Guid.NewGuid():N}"[..12];
            using (var reg = await http.PostAsync("/api/auth/register", new StringContent(
                JsonSerializer.Serialize(new { username, password = "secret123" }),
                System.Text.Encoding.UTF8, "application/json")))
            {
                Assert.Equal(0, JsonDocument.Parse(await reg.Content.ReadAsStringAsync())
                    .RootElement.GetProperty("code").GetInt32());
            }
            await using (var db = _factory.CreateDbContext())
            {
                db.Devices.Single(d => d.Id == b.DeviceId).OwnerUserId =
                    db.Users.Single(u => u.Username == username).Id;
                await db.SaveChangesAsync();
            }
            using (var login = await http.PostAsync("/api/auth/login", new StringContent(
                JsonSerializer.Serialize(new { username, password = "secret123" }),
                System.Text.Encoding.UTF8, "application/json")))
            {
                Assert.Equal(0, JsonDocument.Parse(await login.Content.ReadAsStringAsync())
                    .RootElement.GetProperty("code").GetInt32());
            }
            await WaitStateAsync(http, "failed");

            // 断线注入：同 deviceId 顶替连接（服务端 replaced_by_new_session 踢掉 runtime 会话）
            var kicker = new ControlClient([$"127.0.0.1:{_port}"],
                deviceId: a.DeviceId, deviceSecret: a.DeviceSecret);
            var deadline = Environment.TickCount64 + 5000;
            while (Environment.TickCount64 < deadline && kicker.State != ControlClientState.Established)
                await Task.Delay(20);
            Assert.Equal(ControlClientState.Established, kicker.State);
            await kicker.DisposeAsync();

            // 重连沿（修 A）：凭据自动重放——web 登录态与服务端会话登录绑定恢复
            await WaitLogAsync(logs, $"重连后已自动重放登录（{username}");
            // failed 映射兜底（修 C）：会话重建沿补试一轮
            await WaitLogAsync(logs, "补试 failed 映射");
            using (var me = await http.GetAsync("/api/auth/me"))
            {
                var meRoot = JsonDocument.Parse(await me.Content.ReadAsStringAsync()).RootElement.GetProperty("data");
                Assert.Equal(username, meRoot.GetProperty("username").GetString());
                Assert.Equal("normal", meRoot.GetProperty("mode").GetString());
            }
            // 服务端会话登录绑定就位（修 A 重放与修 D 继承殊途同归；修复前重连即丢——此处必 null）
            deadline = Environment.TickCount64 + 5000;
            while (Environment.TickCount64 < deadline && _registry.TryGet(a.DeviceId)?.OwnerUserId is null)
                await Task.Delay(20);
            Assert.NotNull(_registry.TryGet(a.DeviceId)?.OwnerUserId);
        }
        await runtime.DisposeAsync();
    }

    // ── ② 未注册向导模式：占位地址 → 向导换址（退避唤醒）→ 注册 → 自动续跑注册后路径 ──

    [Fact]
    public async Task 未注册_向导模式_注册完成后自动应用网卡建立通道()
    {
        var dir = Path.Combine(_rootDir, "fresh");
        Directory.CreateDirectory(dir);
        var settings = new SettingsStore(dir);
        await settings.SaveAsync(new ClientSettings { ServerAddrs = [], LocalWebPort = FreePort() });

        var runtime = new ClientRuntime(new ClientRuntimeOptions { BaseDir = dir, NicOverride = _nic });
        await runtime.StartAsync(); // 未注册分支：启动即返回（向导模式）
        using var http = LocalHttp(runtime);
        try
        {
            Assert.Equal("unregistered", await GetPhaseAsync(http));

            // 向导注册（default 模式）：settings 换址落盘 → 占位连接换表（退避唤醒）→ NeedRegister → 0x10
            using var response = await http.PostAsync("/api/wizard/register", new StringContent(
                JsonSerializer.Serialize(new { serverAddr = $"127.0.0.1:{_port}", mode = "default", deviceName = "rt-fresh" }),
                System.Text.Encoding.UTF8, "application/json"));
            var root = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
            Assert.Equal(0, root.GetProperty("code").GetInt32());
            Assert.NotEqual(JsonValueKind.Null, root.GetProperty("data").GetProperty("remoteCode").ValueKind);

            // RegistrationCompleted → 注册后路径（网卡/通道）自动续跑
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            while (await GetPhaseAsync(http) != "running")
                await Task.Delay(200, cts.Token);
            Assert.Contains(IPAddress.Parse("100.64.0.2"), _nic.Ensured); // RegisterAck 统一下发 .2（OQ-13）
        }
        finally
        {
            await runtime.DisposeAsync();
        }
    }

    // ── ④ 卸载清理（M2-25，FR-C-203）：解绑确认 + 残留全清 + purge ──

    [Fact]
    public async Task 卸载清理_unbind确认_网卡残留监听全清_purge删除配置()
    {
        var b = await SeedRegisteredWithMappingAsync("un-b", null);
        var a = await SeedRegisteredWithMappingAsync("un-a", b);
        var dirA = Path.Combine(_rootDir, "un-a");

        // 起服务：映射恢复=监听已绑（punch→failed 确定性，同用例①口径）
        var runtime = new ClientRuntime(new ClientRuntimeOptions { BaseDir = dirA, NicOverride = _nic });
        await runtime.StartAsync();
        using (var http = LocalHttp(runtime))
            await WaitStateAsync(http, "failed");
        var state = new StateStore(dirA);
        state.Load();
        var port = state.State.Mappings.Single(m => m.Enabled).LocalPort;
        await runtime.DisposeAsync(); // 服务停止：全部映射监听释放

        // 监听已自由（卸载链路的前置：释放全部映射监听）
        var rebind = new TcpListener(IPAddress.Loopback, port);
        rebind.Start();
        rebind.Stop();

        // 卸载（替身在位=遗留适配器模拟；--unbind + --purge）
        var report = await ClientUninstaller.RunAsync(new UninstallOptions
        { BaseDir = dirA, Unbind = true, Purge = true, NicOverride = _nic });

        Assert.True(report.UnbindConfirmed, "0x12 解绑须确认（服务端断连）");
        Assert.True(report.NicRemoved);
        Assert.True(report.LeftoverRemoved, "遗留适配器须移除");
        Assert.True(report.ConfigDeleted);
        Assert.False(_nic.Exists); // 适配器/监听/文件残留清单为空
        Assert.False(Directory.Exists(dirA));

        // 服务端侧：0x12 全关联清理（设备行+本人映射）
        await using var db = _factory.CreateDbContext();
        Assert.False(await db.Devices.AnyAsync(d => d.Id == a.DeviceId));
        Assert.False(await db.Mappings.AnyAsync(m => m.OwnerDeviceId == a.DeviceId
            || m.TargetDeviceId == a.DeviceId));
    }

    [Fact]
    public async Task 卸载清理_默认keep_config_配置与服务端记录保留()
    {
        var a = await SeedRegisteredWithMappingAsync("un-keep", null);
        var dir = Path.Combine(_rootDir, "un-keep");
        var runtime = new ClientRuntime(new ClientRuntimeOptions { BaseDir = dir, NicOverride = _nic });
        await runtime.StartAsync();
        await runtime.DisposeAsync();

        var report = await ClientUninstaller.RunAsync(new UninstallOptions { BaseDir = dir, NicOverride = _nic });

        Assert.False(report.UnbindConfirmed); // 未请求解绑
        Assert.False(report.ConfigDeleted);   // --keep-config 默认
        Assert.True(Directory.Exists(dir));
        Assert.True(File.Exists(Path.Combine(dir, "state.json")));
        await using var db = _factory.CreateDbContext();
        Assert.True(await db.Devices.AnyAsync(d => d.Id == a.DeviceId)); // 服务端记录保留
    }


    // ── ⑥ 升级引导（M2-26，FR-C-904）：注入版本拒答 → 0x03 数据链路完整 ──

    [Fact]
    public async Task 升级引导_版本拒答_升级信息事件与本地代理数据链路完整()
    {
        // 服务端升级参数（server_config update_* 键，M2-14 语义：max=宿主编译版本，min=配置 clamp）
        await using (var db = _factory.CreateDbContext())
        {
            db.ServerConfig.Single(c => c.Key == "update_latest_version").Value = "9.9.9";
            db.ServerConfig.Single(c => c.Key == "update_url").Value = "https://dl.example.com/p2p";
            db.ServerConfig.Single(c => c.Key == "update_notes").Value = "协议升级，请手动更新";
            await db.SaveChangesAsync();
        }

        // 未注册向导模式：StartAsync 即返回；服务端 HandleHelloAsync 先校版本再判注册——拒答可达
        var dir = Path.Combine(_rootDir, "upg");
        Directory.CreateDirectory(dir);
        var settings = new SettingsStore(dir);
        await settings.SaveAsync(new ClientSettings { ServerAddrs = [$"127.0.0.1:{_port}"], LocalWebPort = FreePort() });

        var runtime = new ClientRuntime(new ClientRuntimeOptions
        {
            BaseDir = dir,
            NicOverride = _nic,
            // 注入版本拒答：Hello 协议版本越界（服务端 5004 → 0x03 受理窗）
            ControlProtocolVersionOverride = (ushort)(ProtocolVersion.Current + 1),
        });
        // 打开动作以事件断言（清单完成判定）：每轮拒答均触发（浏览器去重在宿主层）
        var tcs = new TaskCompletionSource<UpdateInfoResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
        runtime.UpgradeRequired += info => tcs.TrySetResult(info);
        await runtime.StartAsync();
        try
        {
            var info = await tcs.Task.WaitAsync(TimeSpan.FromSeconds(15));
            Assert.Equal("9.9.9", info.LatestVersion);
            Assert.Equal(1, info.MinProtocol); // update_min_protocol 种子默认 1
            Assert.Equal(ProtocolVersion.Current, info.MaxProtocol);
            Assert.Equal("https://dl.example.com/p2p", info.UpgradeUrl);
            Assert.Equal("协议升级，请手动更新", info.Notes);

            // 本地代理（04 §2.7）：通道永不能建立 → 拒答窗口缓存回落正是 /upgrade 页数据源
            using (var http = LocalHttp(runtime))
            {
                using var response = await http.GetAsync("/api/upgrade/info");
                var root = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
                Assert.Equal(0, root.GetProperty("code").GetInt32());
                var data = root.GetProperty("data");
                Assert.Equal("9.9.9", data.GetProperty("latestVersion").GetString());
                Assert.Equal(1, data.GetProperty("minProtocol").GetInt32());
                Assert.Equal(ProtocolVersion.Current, (ushort)data.GetProperty("maxProtocol").GetInt32());
                Assert.Equal("https://dl.example.com/p2p", data.GetProperty("upgradeUrl").GetString());
                Assert.Equal("协议升级，请手动更新", data.GetProperty("notes").GetString());
            }
        }
        finally
        {
            await runtime.DisposeAsync();
        }
    }

    // ── ③ 网卡降级不阻断：EnsureAsync 失败 → 通道/本地 Web 照常运行 ──

    [Fact]
    public async Task 网卡应用失败_降级告警不阻断_通道照常建立()
    {
        await SeedRegisteredWithMappingAsync("rt-degraded", null);
        var runtime = new ClientRuntime(new ClientRuntimeOptions
        {
            BaseDir = Path.Combine(_rootDir, "rt-degraded"),
            NicOverride = new FailingNicManager(),
        });
        var logs = new List<string>();
        runtime.Log += logs.Add;
        await runtime.StartAsync();
        try
        {
            using var http = LocalHttp(runtime);
            Assert.Equal("running", await GetPhaseAsync(http)); // 降级不阻断（05 §1.1）
            Assert.Contains(logs, l => l.Contains("降级"));
        }
        finally
        {
            await runtime.DisposeAsync();
        }
    }

    /// <summary>网卡失败替身：EnsureAsync 恒抛（降级路径验证）。CheckHealth 亦报缺失
    ///（自愈循环会周期重试 Ensure——默认 30s 周期在测试时长内不触发）。</summary>
    private sealed class FailingNicManager : INicManager
    {
#pragma warning disable CS0067 // 接口事件保留位
        public event Action<string>? Degraded;
#pragma warning restore CS0067

        public Task<NicHandle> EnsureAsync(IPAddress virtualIp, CancellationToken ct = default)
            => throw new NicException("测试注入：网卡应用失败");

        public Task RemoveAsync(CancellationToken ct = default) => Task.CompletedTask;

        public NicHealth CheckHealth(IPAddress expectedIp) => new(NicHealthState.AdapterMissing, null);

        public Task<bool> RemoveLeftoverAsync(CancellationToken ct = default) => Task.FromResult(false);
    }
}
