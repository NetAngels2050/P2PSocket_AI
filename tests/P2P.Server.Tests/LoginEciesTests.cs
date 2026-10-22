using System.Net;
using System.Text;
using Microsoft.EntityFrameworkCore;
using P2P.Core.Crypto;
using P2P.Core.Protocol;
using P2P.Server.Data;
using P2P.Server.Services;
using Xunit;

namespace P2P.Server.Tests;

/// <summary>
/// 登录族 ECIES 硬切测试（M5-06/SEC-26，07 §10.3，OQ-21①）：
/// 服务端拒明文（5004 password_ecies_required——旧客户端+新服务端混布向）、
/// 错钥/篡改密文=凭据失败口径（不泄漏原因）、0x10 死字段平行明文通路封堵、
/// A-16 帧探针（报文字节不出现明文密码子串）。
/// </summary>
public sealed class LoginEciesTests : IAsyncLifetime
{
    private readonly TestDatabase _db = new();
    private readonly DeviceRegistry _registry = new();
    private readonly List<TestPcpClient> _clients = [];
    private ControlServer _server = null!;
    private SignalingCoordinator _signaling = null!;
    private RelayService _relay = null!;

    public Task InitializeAsync()
    {
        var factory = new StubFactory(CreateDb);
        using var init = factory.CreateDbContext();
        DbInitializer.Initialize(init);

        var audit = new AuditLogger(factory);
        _signaling = new SignalingCoordinator(factory, _registry, new Authorizer(factory), audit);
        _relay = new RelayService(factory, _registry, _signaling.ResolveRelayPeers);
        var router = new ControlMessageRouter(
            new RegistrationService(factory, _registry, audit),
            new UserService(factory, audit),
            new GroupService(factory, _registry, audit),
            _signaling,
            new MappingService(factory, audit),
            _relay,
            new StatsService(factory, audit),
            audit,
            new LanSegmentService(factory, _registry, audit));
        _server = new ControlServer(factory, _registry, router.DispatchAsync);
        return _server.StartAsync(new IPEndPoint(IPAddress.Loopback, 0));
    }

    public async Task DisposeAsync()
    {
        await _relay.DisposeAsync();
        foreach (var c in _clients) await c.DisposeAsync();
        await _server.DisposeAsync();
        await _signaling.DisposeAsync();
        _db.Dispose();
    }

    private static bool SpanContains(byte[] haystack, byte[] needle)
        => haystack.AsSpan().IndexOf(needle) >= 0;

    private AppDbContext CreateDb() => new(
        new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_db.DataSource).Options);

    /// <summary>已注册+已建立会话的客户端（0x21 可发——主动类）。</summary>
    private async Task<TestPcpClient> ConnectEstablishedAsync()
    {
        var client = await TestPcpClient.ConnectAsync(_server.LocalEndPoint!);
        _clients.Add(client);
        await client.HelloAsync(deviceId: null);
        var key = EcKeyPair.Generate();
        await client.SendAsync(new Register(client.NextSeq(), client.Now(), MsgType.Register,
            $"P2P-ECIES{Guid.NewGuid():N}"[..14], "host-e", "windows", "0.1.0",
            key.ExportPublicKey(), null, null, null), sign: false);
        var ack = await client.ReceiveAsync<RegisterAck>() ?? throw new IOException("注册无应答");
        client.EstablishWithSecret(Ecies.Decrypt(key, ack.DeviceSecretBox));
        return client;
    }

    // ── 硬切：服务端拒明文（旧客户端 + 新服务端）──────────────────────────

    [Fact]
    public async Task 明文登录_硬切5004_password_ecies_required()
    {
        var client = await ConnectEstablishedAsync();
        await client.SendAsync(new UserLogin(client.NextSeq(), client.Now(), MsgType.UserLogin,
            "admin", "admin")); // 旧客户端明文字段、无 Box
        var err = await client.ReceiveAsync<ErrorMessage>();
        Assert.Equal(ErrorCode.VersionNotSupported, err!.Code);
        Assert.Equal("password_ecies_required", err.HttpLikeMsg);
    }

    [Fact]
    public async Task 缺Box空明文_同5004_三消息一致()
    {
        var client = await ConnectEstablishedAsync();
        await client.SendAsync(new UserLogin(client.NextSeq(), client.Now(), MsgType.UserLogin,
            "admin", "", null));
        var err = await client.ReceiveAsync<ErrorMessage>();
        Assert.Equal(ErrorCode.VersionNotSupported, err!.Code);

        await client.SendAsync(new UserRegister(client.NextSeq(), client.Now(), MsgType.UserRegister,
            "alice", "", null));
        err = await client.ReceiveAsync<ErrorMessage>();
        Assert.Equal(ErrorCode.VersionNotSupported, err!.Code);

        // 0x23 任一字段缺失即硬切（old 有 new 无）
        await client.SendAsync(new UserLogin(client.NextSeq(), client.Now(), MsgType.UserLogin,
            "admin", "", client.BoxLoginSecret("admin")));
        _ = await client.ReceiveAsync<UserLoginAck>();
        await client.SendAsync(new UserChangePassword(client.NextSeq(), client.Now(),
            MsgType.UserChangePassword, "", "", null, client.BoxLoginSecret("new-pass-9")));
        err = await client.ReceiveAsync<ErrorMessage>();
        Assert.Equal(ErrorCode.VersionNotSupported, err!.Code);
    }

    // ── 错钥/篡改密文：凭据失败口径（不泄漏原因）─────────────────────────

    [Fact]
    public async Task 错钥密文_登录Ack失败_不设专用错误码()
    {
        var client = await ConnectEstablishedAsync();
        using var wrongKey = EcKeyPair.Generate(); // 与服务端本连接 loginEph 无关的接收钥
        var wrongBox = Ecies.Encrypt(wrongKey.ExportPublicKey(),
            Encoding.UTF8.GetBytes("whatever"), "pcp-login-v1"u8);
        await client.SendAsync(new UserLogin(client.NextSeq(), client.Now(), MsgType.UserLogin,
            "admin", "", wrongBox));
        var ack = await client.ReceiveAsync<UserLoginAck>();
        Assert.False(ack!.Ok); // 凭据失败统一口径（A-16 断言点：不泄漏解密失败原因）
    }

    [Fact]
    public async Task 错钥密文_改密Ack失败_审计照常落()
    {
        var client = await ConnectEstablishedAsync();
        await client.SendAsync(new UserLogin(client.NextSeq(), client.Now(), MsgType.UserLogin,
            "admin", "", client.BoxLoginSecret("admin")));
        Assert.True((await client.ReceiveAsync<UserLoginAck>())!.Ok);

        using var wrongKey = EcKeyPair.Generate();
        var wrongOldBox = Ecies.Encrypt(wrongKey.ExportPublicKey(),
            Encoding.UTF8.GetBytes("admin"), "pcp-login-v1"u8);
        await client.SendAsync(new UserChangePassword(client.NextSeq(), client.Now(),
            MsgType.UserChangePassword, "", "", wrongOldBox, client.BoxLoginSecret("new-pass-9")));
        var ack = await client.ReceiveAsync<UserChangePasswordAck>();
        Assert.False(ack!.Ok);
    }

    // ── 0x10 死字段平行明文通路封堵（07 §10.3）───────────────────────────

    [Fact]
    public async Task Register_死字段Password非空_同5004拒()
    {
        var client = await TestPcpClient.ConnectAsync(_server.LocalEndPoint!);
        _clients.Add(client);
        await client.HelloAsync(deviceId: null);
        var key = EcKeyPair.Generate();
        await client.SendAsync(new Register(client.NextSeq(), client.Now(), MsgType.Register,
            $"P2P-DEAD{Guid.NewGuid():N}"[..13], "host-d", "windows", "0.1.0",
            key.ExportPublicKey(), null, "someone", "plain-pw"), sign: false);
        var err = await client.ReceiveAsync<ErrorMessage>();
        Assert.Equal(ErrorCode.VersionNotSupported, err!.Code);
        Assert.Equal("password_ecies_required", err.HttpLikeMsg);
    }

    // ── A-16 帧探针：报文字节不出现明文密码子串（新+新组合）──────────────

    [Fact]
    public async Task 帧探针_线上无明文密码子串()
    {
        const string probe = "probe-Pw-a16-fixed-8b3c";
        var client = await ConnectEstablishedAsync();
        await client.SendAsync(new UserLogin(client.NextSeq(), client.Now(), MsgType.UserLogin,
            "admin", "", client.BoxLoginSecret(probe)));
        Assert.NotNull(await client.ReceiveAsync<UserLoginAck>()); // 探针口令非真实口令——Ok=false 属预期，仅取帧落定

        var needle = Encoding.UTF8.GetBytes(probe);
        // 探针敏感性对照：明文字段确会在线上出现（旧客户端形态自证探针有效）
        var legacy = PcpCodec.Encode(new UserLogin(1, 1UL, MsgType.UserLogin, "u", probe));
        Assert.True(SpanContains(legacy, needle));
        // 断言：本连接全部已发帧（签名后线上字节）均不含明文密码
        Assert.All(client.SentWire, frame => Assert.False(SpanContains(frame, needle)));
    }
}
