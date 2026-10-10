// M4-05 基准世界装配：in-proc 服务端 + 双 ClientRuntime + NatSimulator + echo（镜像
// ScenarioIntegrationTests 装配模式——同一真实控制协议/打洞协议/承载路径，09 §2.2 回环别名拓扑）。
// L1 口径（TD-24）：全链本机回环，吞吐/延迟为基线测量（≠真实网络性能，报告如实标注）。
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using P2P.Client.Hosting;
using P2P.Client.Storage;
using P2P.Core.Crypto;
using P2P.Core.Stun;
using P2P.IntegrationTests.NatSimulator;
using P2P.Server;
using P2P.Server.Data;
using P2P.Server.Services;

namespace P2P.Bench;

/// <summary>NAT 世界形态：<see cref="Udp"/>=UDP 打洞路径（UdpNatSimulator 模式对，TCP 侧恒等替身）；
/// <see cref="Tcp"/>=TCP 打洞路径（TcpNatSimulator 端口平移，UDP 侧 FullCone）。</summary>
internal enum BenchNatKind { Udp, Tcp }

/// <summary>一次基准世界：独立库/服务端/中继/双客户端/NAT（世界销毁即样本隔离——矩阵每格独立世界）。</summary>
internal sealed class BenchWorld : IAsyncDisposable
{
    public BenchDatabase Db { get; } = new();
    private readonly DeviceRegistry _registry = new();
    private readonly List<SignalingCoordinator> _signalings = [];
    private readonly List<RelayService> _relays = [];
    private readonly List<ControlServer> _servers = [];
    private readonly List<ClientRuntime> _runtimes = [];
    private readonly List<HttpClient> _https = [];
    private readonly List<TcpListener> _echoListeners = [];
    private CancellationTokenSource? _echoCts;
    private UdpNatSimulator? _sim;
    private StubStunUpstream? _upstream;
    private TcpStunStub? _tcpStun;
    private TcpNatSimulator? _tcpSim;
    private readonly string _rootDir;
    private int _port;
    private readonly Action<string> _log;

    private BenchWorld(string rootDir, int port, Action<string> log)
    {
        _rootDir = rootDir;
        _port = port;
        _log = log;
    }

    /// <summary>拉起世界：库初始化（admin+默认分组）→ 服务端（控制面+中继数据面）→ NAT → 客户端 A/B。
    /// udpModes 仅 Udp 世界消费；Tcp 世界固定 FullCone×FullCone（承载面）+TcpNatSimulator 端口平移。
    /// tcpModes/perturbB 仅 Tcp 世界消费。</summary>
    public static async Task<BenchWorld> CreateAsync(BenchNatKind kind, string tag,
        (IPAddress Ip, UdpNatMode Mode) udpA, (IPAddress Ip, UdpNatMode Mode) udpB,
        TcpNatMode tcpModeA = TcpNatMode.SymmetricSequential, TcpNatMode tcpModeB = TcpNatMode.SymmetricSequential,
        int perturbB = 0, int punchConcurrency = 1, Action<string>? log = null)
    {
        log ??= static _ => { };
        var rootDir = Path.Combine(Path.GetTempPath(), $"p2p-bench-{tag}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(rootDir);
        var world = new BenchWorld(rootDir, 0, log);
        try
        {
            using (var init = world.Db.Factory.CreateDbContext())
                DbInitializer.Initialize(init);
            var server = await world.StartServerAsync();
            world._port = ((IPEndPoint)server.LocalEndPoint!).Port;

            // NAT 世界（09 §2.2：模拟公网 127.0.0.1，STUN 派生 :3478）
            world._upstream = new StubStunUpstream();
            await world._upstream.StartAsync();
            world._sim = new UdpNatSimulator(new UdpNatOptions { Upstream = world._upstream.Endpoint, StunPort = 3478 });
            await world._sim.StartAsync();
            world._sim.RegisterClient(udpA.Ip, udpA.Mode, "A");
            world._sim.RegisterClient(udpB.Ip, udpB.Mode, "B");
            if (kind == BenchNatKind.Tcp)
                world._tcpSim = await world.CreateTcpSimulatorAsync(udpA.Ip, tcpModeA, udpB.Ip, tcpModeB, perturbB);
            else
            {
                world._tcpStun = new TcpStunStub();
                world._tcpStun.Start();
            }

            var group = await world.CreateGroupAsync();
            var a = await world.SeedClientAsync($"{tag}-a", udpA.Ip, group, punchConcurrency);
            var b = await world.SeedClientAsync($"{tag}-b", udpB.Ip, group, punchConcurrency);
            world.ClientA = a;
            world.ClientB = b;
            world.HttpA = await world.StartRuntimeAsync(a);
            world.HttpB = await world.StartRuntimeAsync(b);
            await world.WaitPhaseAsync(world.HttpA, "running");
            await world.WaitPhaseAsync(world.HttpB, "running");
            return world;
        }
        catch
        {
            await world.DisposeAsync();
            throw;
        }
    }

    public SeededClient ClientA { get; private set; } = null!;
    public SeededClient ClientB { get; private set; } = null!;
    public HttpClient HttpA { get; private set; } = null!;
    public HttpClient HttpB { get; private set; } = null!;

    private async Task<TcpNatSimulator> CreateTcpSimulatorAsync(IPAddress ipA, TcpNatMode modeA,
        IPAddress ipB, TcpNatMode modeB, int perturbB)
    {
        var sim = new TcpNatSimulator(new TcpNatOptions { StunPort = 3478, PortBase = 20500 });
        sim.RegisterClient(ipA, modeA, "A");
        sim.RegisterClient(ipB, modeB, "B", perturbB);
        await sim.StartAsync();
        return sim;
    }

    public sealed record SeededClient(Guid DeviceId, byte[] DeviceSecret, string RemoteCode, string Dir, IPAddress Ip);

    private async Task<ControlServer> StartServerAsync()
    {
        var audit = new AuditLogger(Db.Factory);
        var signaling = new SignalingCoordinator(Db.Factory, _registry, new Authorizer(Db.Factory), audit);
        var relay = new RelayService(Db.Factory, _registry, signaling.ResolveRelayPeers);
        var pusher = new DeviceListPusher(Db.Factory, _registry);
        var router = new ControlMessageRouter(
            new RegistrationService(Db.Factory, _registry, audit),
            new UserService(Db.Factory, audit),
            new GroupService(Db.Factory, _registry, audit, pusher),
            signaling,
            new MappingService(Db.Factory, audit),
            relay,
            new StatsService(Db.Factory, audit),
            audit);
        var server = new ControlServer(Db.Factory, _registry, router.DispatchAsync);
        await server.StartAsync(new IPEndPoint(IPAddress.Loopback, 0));
        await relay.StartAsync(0, 0); // 中继数据面系统分配端口（Grant 端点来源）
        _signalings.Add(signaling);
        _relays.Add(relay);
        _servers.Add(server);
        return server;
    }

    private async Task<Group> CreateGroupAsync()
    {
        await using var db = Db.Factory.CreateDbContext();
        var group = new Group
        {
            Id = Guid.NewGuid(),
            Name = $"bn-{Guid.NewGuid():N}"[..16],
            OwnerUserId = db.Users.Single(u => u.IsAdmin).Id,
            IsDefault = false,
            JoinPolicy = "free",
            CreatedAt = DateTime.UtcNow,
        };
        db.Groups.Add(group);
        await db.SaveChangesAsync();
        return group;
    }

    /// <summary>种已注册设备 + 客户端 state/settings（Scenario.SeedClientAsync 同模式）。</summary>
    private async Task<SeededClient> SeedClientAsync(string name, IPAddress ip, Group group, int punchConcurrency)
    {
        var deviceId = Guid.NewGuid();
        var secret = RandomGenerator.Bytes(32);
        var remoteCode = FakeRemoteCode();
        using var kp = EcKeyPair.Generate();
        await using var db = Db.Factory.CreateDbContext();
        db.Devices.Add(new Device
        {
            Id = deviceId,
            DeviceName = name,
            Os = "windows",
            ClientVersion = "1.0.0",
            MacCode = $"BN-{Guid.NewGuid():N}"[..16],
            RemoteCode = remoteCode,
            VirtualIp = ip.ToString(),
            StaticPubKey = kp.ExportPublicKey(),
            DeviceSecret = secret,
            LastSeenAt = DateTime.UtcNow,
            CreatedAt = DateTime.UtcNow,
        });
        db.GroupMembers.Add(new GroupMember { Id = Guid.NewGuid(), GroupId = group.Id, DeviceId = deviceId, Approved = true });
        await db.SaveChangesAsync();

        var dir = Path.Combine(_rootDir, name);
        Directory.CreateDirectory(dir);
        var store = new StateStore(dir);
        store.State.DeviceId = deviceId;
        store.State.DeviceSecret = secret;
        store.State.StaticPrivateKey = kp.ExportPrivateKey();
        store.State.RemoteCode = remoteCode;
        store.State.VirtualIp = ip.ToString();
        await store.SaveAsync();
        var settings = new SettingsStore(dir);
        await settings.SaveAsync(new ClientSettings
        {
            ServerAddrs = [$"127.0.0.1:{_port}"],
            LocalWebPort = FreePort(),
            PunchConcurrency = punchConcurrency,
        });
        return new SeededClient(deviceId, secret, remoteCode, dir, ip);
    }

    private async Task<HttpClient> StartRuntimeAsync(SeededClient c)
    {
        var runtime = new ClientRuntime(new ClientRuntimeOptions
        {
            BaseDir = c.Dir,
            NicOverride = new StubNicManager(),
            PunchBindOverride = c.Ip,
        });
        runtime.Log += m => _log($"[{c.Ip}] {m}");
        await runtime.StartAsync();
        _runtimes.Add(runtime);
        var http = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{runtime.WebPort}") };
        _https.Add(http);
        return http;
    }

    // ── echo 服务（吞吐/延迟测量的载荷终点）────────────────────────────

    public int StartEcho()
    {
        var port = FreePort();
        _echoCts ??= new CancellationTokenSource();
        var listener = new TcpListener(IPAddress.Loopback, port);
        listener.Start();
        _echoListeners.Add(listener);
        var ct = _echoCts.Token;
        _ = Task.Run(async () =>
        {
            while (!ct.IsCancellationRequested)
            {
                TcpClient client;
                try { client = await listener.AcceptTcpClientAsync(ct); }
                catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException) { break; }
                _ = Task.Run(() => EchoClientAsync(client), ct);
            }
        });
        return port;
    }

    private static async Task EchoClientAsync(TcpClient client)
    {
        using var _ = client;
        try
        {
            await using var stream = client.GetStream();
            var buf = new byte[64 * 1024];
            while (true)
            {
                var n = await stream.ReadAsync(buf);
                if (n <= 0) break;
                await stream.WriteAsync(buf.AsMemory(0, n));
            }
        }
        catch { /* 连接断开 */ }
    }

    // ── HTTP 工具（真实本地 API → 控制协议全链路）──────────────────────

    public async Task<JsonElement> GetAsync(string path)
    {
        using var resp = await HttpA.GetAsync(path);
        return JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
    }

    public async Task<JsonElement> PostAsync(HttpClient http, string path, object? body)
    {
        using var content = body is null ? null
            : new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
        using var resp = await http.PostAsync(path, content);
        return JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
    }

    public async Task<JsonElement> PutAsync(HttpClient http, string path, object? body)
    {
        using var content = body is null ? null
            : new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
        using var resp = await http.PutAsync(path, content);
        return JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
    }

    public async Task<Guid> CreateMappingAsync(HttpClient http, ushort localPort, string targetRemoteCode,
        ushort targetPort, string proto = "tcp", string name = "bench")
    {
        var created = await PostAsync(http, "/api/mappings", new
        {
            name,
            localPort,
            proto,
            targetRemoteCode,
            targetAddr = "self",
            targetPort,
        });
        EnsureOk(created, "创建映射");
        return created.GetProperty("data").GetProperty("mappingId").GetGuid();
    }

    /// <summary>启用映射并返回启用时刻（ Stopwatch 口径的建立耗时起点）。</summary>
    public async Task<(Guid Id, long StartTs)> EnableMappingAsync(HttpClient http, Guid id)
    {
        var sw = StopwatchStart();
        var enabled = await PostAsync(http, $"/api/mappings/{id}/enable", null);
        EnsureOk(enabled, "启用映射");
        return (id, sw);
    }

    /// <summary>轮询映射终态（direct/relay/failed；200ms 轮询粒度计入 elapsed 口径；startTs=启用时刻
    /// [EnableMappingAsync 返回]，seconds 上限后返回 "timeout"——矩阵/耗时样本如实记录不抛断言）。</summary>
    public async Task<(string State, long ElapsedMs)> WaitTerminalAsync(HttpClient http, Guid mappingId,
        long startTs, int seconds = 45)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(seconds));
        while (!cts.IsCancellationRequested)
        {
            using var resp = await http.GetAsync("/api/mappings");
            var root = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
            var item = root.GetProperty("data").GetProperty("items").EnumerateArray()
                .FirstOrDefault(i => i.GetProperty("mappingId").GetGuid() == mappingId);
            var state = item.ValueKind == JsonValueKind.Undefined ? "" : item.GetProperty("state").GetString()!;
            if (state is "direct" or "relay" or "failed")
                return (state, StopwatchElapsed(startTs));
            await Task.Delay(200, cts.Token);
        }
        return ("timeout", StopwatchElapsed(startTs));
    }

    /// <summary>对端设备开中继回退（peers.json relayFallback=true——0x74 回退资格前提；失败即抛）。</summary>
    public async Task EnableRelayFallbackAsync()
    {
        var put = await PutAsync(HttpA, $"/api/peers/{ClientB.DeviceId}", new { relayFallback = true });
        if (put.GetProperty("code").GetInt32() != 0)
            throw new InvalidOperationException($"开回退失败：{put}");
    }

    /// <summary>禁用映射（耗时基准多轮样本间复位）。</summary>
    public async Task DisableMappingAsync(HttpClient http, Guid id)
    {
        var resp = await PostAsync(http, $"/api/mappings/{id}/disable", null);
        EnsureOk(resp, "禁用映射");
    }

    /// <summary>服务端 punch_stats 0x72 结果分布（direct=success/relay=relay/failed 行——矩阵交叉验证列，
    /// M4-06 报告取数同款查询）。</summary>
    public async Task<Dictionary<string, int>> PunchStatsAsync()
    {
        await using var db = Db.Factory.CreateDbContext();
        return db.PunchStats.AsNoTracking()
            .GroupBy(p => p.Result)
            .ToDictionary(g => g.Key, g => g.Count());
    }

    public async Task<string> GetPhaseAsync(HttpClient http)
    {
        using var resp = await http.GetAsync("/api/system/state");
        var root = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        return root.GetProperty("data").GetProperty("phase").GetString()!;
    }

    public async Task WaitPhaseAsync(HttpClient http, string phase, int seconds = 20)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(seconds));
        while (!cts.IsCancellationRequested)
        {
            if (await GetPhaseAsync(http) == phase) return;
            await Task.Delay(200, cts.Token);
        }
        throw new TimeoutException($"等待 phase={phase} 超时");
    }

    private static void EnsureOk(JsonElement root, string what)
    {
        var code = root.GetProperty("code").GetInt32();
        if (code != 0)
            throw new InvalidOperationException($"{what}失败：code={code} msg={root.GetProperty("msg").GetString()}");
    }

    public static long StopwatchStart() => Environment.TickCount64;

    public static long StopwatchElapsed(long startTs) => Environment.TickCount64 - startTs;

    public static int FreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    public static string FakeRemoteCode()
    {
        const string alphabet = "0123456789abc";
        return new string(RandomGenerator.Bytes(6).Select(b => alphabet[b % alphabet.Length]).ToArray());
    }

    public async ValueTask DisposeAsync()
    {
        if (_echoCts is not null) _echoCts.Cancel();
        foreach (var l in _echoListeners) l.Stop();
        foreach (var r in _runtimes) await r.DisposeAsync();
        foreach (var h in _https) h.Dispose();
        if (_sim is not null) await _sim.DisposeAsync();
        if (_upstream is not null) await _upstream.DisposeAsync();
        if (_tcpStun is not null) await _tcpStun.DisposeAsync();
        if (_tcpSim is not null) await _tcpSim.DisposeAsync();
        foreach (var s in _servers) await s.DisposeAsync();
        foreach (var r in _relays) await r.DisposeAsync();
        foreach (var s in _signalings) await s.DisposeAsync();
        await Task.Delay(200); // 收尾宽限（Scenario 同法）
        Db.Dispose();
        try { Directory.Delete(_rootDir, true); } catch (IOException) { }
    }

    /// <summary>TCP STUN Binding 应答替身（恒等 NAT——UDP 世界的 TCP 侧兜底；镜像 Scenario 私有同类）。</summary>
    internal sealed class TcpStunStub : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 3478);
        private readonly CancellationTokenSource _cts = new();

        public void Start()
        {
            _listener.Start(16);
            _ = Task.Run(async () =>
            {
                try
                {
                    while (true)
                    {
                        var conn = await _listener.AcceptSocketAsync(_cts.Token);
                        _ = Task.Run(() => ServeAsync(conn));
                    }
                }
                catch { /* 停机关闭 */ }
            });
        }

        private async Task ServeAsync(Socket conn)
        {
            try
            {
                using var _ = conn;
                using var stream = new NetworkStream(conn, ownsSocket: false);
                var request = await StunTcpFraming.TryReadAsync(stream, _cts.Token);
                if (request is null) return;
                var tid = request.AsSpan(8, StunCodec.TransactionIdLen).ToArray();
                var remote = (IPEndPoint)conn.RemoteEndPoint!;
                await StunTcpFraming.WriteAsync(stream,
                    StunCodec.BuildBindingResponse(tid, remote.Address, (ushort)remote.Port), _cts.Token);
            }
            catch { /* 单事务尽力而为 */ }
        }

        public async ValueTask DisposeAsync()
        {
            _cts.Cancel();
            _listener.Stop();
            await Task.Delay(50);
            _cts.Dispose();
        }
    }
}
