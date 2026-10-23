using System.Net;
using Microsoft.EntityFrameworkCore;
using P2P.Client.Control;
using P2P.Core.Crypto;
using P2P.Core.Protocol;
using P2P.Server.Data;
using P2P.Server.Services;
using Xunit;

namespace P2P.IntegrationTests;

/// <summary>
/// M5-13 静态数据加密集成验收（SEC-83、07 §14.3）：升级前明文库（device_secret 32B 明文行）→
/// 带钥启动序列（Program 同序：TryCreate → 存量迁移 → 密文工厂起服务）→ 真客户端 ControlClient
/// Hello/Proof 重连 Established+业务往返——凭据透明可验=升级迁移不中断。
/// </summary>
public sealed class DeviceSecretEncryptionIntegrationTests : IAsyncLifetime
{
    private readonly TestDatabase _db = new();
    private readonly DeviceRegistry _registry = new();
    private readonly List<SignalingCoordinator> _signalings = [];
    private readonly List<RelayService> _relays = [];
    private readonly List<ControlServer> _servers = [];
    private int _port;

    public Task InitializeAsync() => Task.CompletedTask; // 一次性场景：全在用例内按升级序组装

    public async Task DisposeAsync()
    {
        foreach (var s in _servers) await s.DisposeAsync();
        foreach (var r in _relays) await r.DisposeAsync();
        foreach (var s in _signalings) await s.DisposeAsync();
        _db.Dispose();
    }

    private AppDbContext PlainDb() => new(
        new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_db.DataSource).Options);

    private static string HexKey() => Convert.ToHexString(RandomGenerator.Bytes(32)).ToLowerInvariant();

    private static Device NewDevice(Guid id, byte[] secret) => new()
    {
        Id = id,
        DeviceName = "enc-it",
        Os = "windows",
        ClientVersion = "0.1.0",
        MacCode = $"EI-{Guid.NewGuid():N}"[..16],
        RemoteCode = FakeRemoteCode(),
        VirtualIp = "100.64.0.2",
        StaticPubKey = new byte[65],
        DeviceSecret = secret,
        LastSeenAt = DateTime.UtcNow,
        CreatedAt = DateTime.UtcNow,
    };

    /// <summary>6 位 0-9+abc（OQ-8 字符集）；仅保证唯一（ControlClientIntegrationTests 同款）。</summary>
    private static string FakeRemoteCode()
    {
        const string alphabet = "0123456789abc";
        return new string(RandomGenerator.Bytes(6).Select(b => alphabet[b % alphabet.Length]).ToArray());
    }

    private async Task StartServerAsync(IDbContextFactory<AppDbContext> factory)
    {
        var audit = new AuditLogger(factory);
        var signaling = new SignalingCoordinator(factory, _registry, new Authorizer(factory), audit);
        var relay = new RelayService(factory, _registry, signaling.ResolveRelayPeers);
        var router = new ControlMessageRouter(
            new RegistrationService(factory, _registry, audit),
            new UserService(factory, audit),
            new GroupService(factory, _registry, audit),
            signaling,
            new MappingService(factory, audit),
            relay,
            new StatsService(factory, audit),
            audit);
        var server = new ControlServer(factory, _registry, router.DispatchAsync);
        await server.StartAsync(new IPEndPoint(IPAddress.Loopback, 0));
        _signalings.Add(signaling);
        _relays.Add(relay);
        _servers.Add(server);
        _port = server.LocalEndPoint!.Port;
    }

    [Fact]
    public async Task 存量明文库_带钥启动迁移后_设备重连不中断()
    {
        // ① 升级前明文库：种子 32B 明文设备行（旧版本存量部署形态）
        var deviceId = Guid.NewGuid();
        var secret = RandomGenerator.Bytes(32);
        using (var db = PlainDb())
        {
            DbInitializer.Initialize(db);
            db.Devices.Add(NewDevice(deviceId, secret));
            await db.SaveChangesAsync();
        }

        // ② 升级后带钥启动（Program 同序）：密钥装配 → 存量迁移
        var cipher = DeviceSecretCipher.TryCreate(HexKey(), null, out var reason);
        Assert.NotNull(cipher);
        Assert.Equal("", reason);
        var (migrated, skipped) = DeviceSecretMigrator.Migrate(new StubFactory(PlainDb), cipher);
        Assert.Equal((1, 0), (migrated, skipped));

        using (var db = PlainDb()) // 裸读断言：明文行已改写 61B 密文（非明文落库）
        {
            var raw = db.Devices.AsNoTracking().Single().DeviceSecret;
            Assert.Equal(61, raw.Length);
            Assert.Equal(cipher.CurrentKeyTag, raw[0]);
        }

        // ③ 密文工厂起服务（转换器+模型分缓存同款装配——工厂入口同源防 options/ctor 脱钩误用）
        await StartServerAsync(ServerDatabase.CreateFactoryFromDataSource(_db.DataSource, cipher));

        // ④ 真客户端重连：Hello/Proof（HMAC 凭据）→ Established + 业务往返
        await using var client = new ControlClient(
            new[] { $"127.0.0.1:{_port}" },
            new ControlClientOptions { HeartbeatInterval = TimeSpan.FromHours(1) },
            deviceId: deviceId,
            deviceSecret: secret);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        await client.WaitReadyAsync(cts.Token);
        Assert.Equal(ControlClientState.Established, client.State);

        var ack = await client.SendRequestAsync<DeviceUpdateAck>(new DeviceUpdate(
            client.NextSeq(), client.TimestampMs(), MsgType.DeviceUpdate, "after-upgrade"));
        Assert.True(ack.Ok);
    }
}
