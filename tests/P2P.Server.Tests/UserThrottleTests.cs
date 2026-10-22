using System.Net;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Time.Testing;
using P2P.Core.Crypto;
using P2P.Core.Protocol;
using P2P.Server.Data;
using P2P.Server.Services;
using Xunit;

namespace P2P.Server.Tests;

/// <summary>
/// M5-04 登录防爆破集成（SEC-63、07 §11）：0x21/0x23 双维阶梯——延迟先于凭据校验、
/// 限流触发=延迟后正常失败应答（不设专用错误码）、账户维成功复位/IP 维仅滑窗衰减
/// （FakeTimeProvider 推进放行；既有 UserTests 不接 throttle，多失败序列不受档位影响）。
/// </summary>
public sealed class UserThrottleTests : IAsyncLifetime
{
    private readonly TestDatabase _db = new();
    private readonly DeviceRegistry _registry = new();
    private readonly List<TestPcpClient> _clients = [];
    private readonly FakeTimeProvider _time = new(DateTimeOffset.UtcNow);
    private ControlServer _server = null!;
    private SignalingCoordinator _signaling = null!;
    private RelayService _relay = null!;
    private LoginThrottle _throttle = null!;

    public Task InitializeAsync()
    {
        var factory = new StubFactory(CreateDb);
        using var init = factory.CreateDbContext();
        DbInitializer.Initialize(init);

        var audit = new AuditLogger(factory, _time);
        _throttle = new LoginThrottle(time: _time); // 缺省 900s 窗/8000ms 帽（03 §2.8 种子口径）
        _signaling = new SignalingCoordinator(factory, _registry, new Authorizer(factory), audit, _time);
        _relay = new RelayService(factory, _registry, _signaling.ResolveRelayPeers, time: _time);
        var router = new ControlMessageRouter(
            new RegistrationService(factory, _registry, audit),
            new UserService(factory, audit, _time, throttle: _throttle),
            new GroupService(factory, _registry, audit, time: _time),
            _signaling,
            new MappingService(factory, audit),
            _relay,
            new StatsService(factory, audit), audit);
        _server = new ControlServer(factory, _registry, router.DispatchAsync); // 控制面时钟=System（ts 校验）
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

    private AppDbContext CreateDb() => new(
        new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_db.DataSource).Options);

    /// <summary>注册设备+用户并完成首登（首登无失败零延迟——正常低频路径零感知）。</summary>
    private async Task<TestPcpClient> ConnectLoggedInAsync(string username, string password)
    {
        var client = await TestPcpClient.ConnectAsync(_server.LocalEndPoint!);
        _clients.Add(client);
        await client.HelloAsync(deviceId: null);
        var key = EcKeyPair.Generate();
        await client.SendAsync(new Register(client.NextSeq(), client.Now(), MsgType.Register,
            $"P2P-THR{Guid.NewGuid():N}"[..14], "host-t", "windows", "0.1.0",
            key.ExportPublicKey(), null, null, null), sign: false);
        var ack = await client.ReceiveAsync<RegisterAck>() ?? throw new IOException("注册无应答");
        client.EstablishWithSecret(Ecies.Decrypt(key, ack.DeviceSecretBox));
        await client.SendAsync(new UserRegister(client.NextSeq(), client.Now(), MsgType.UserRegister, username, "", client.BoxLoginSecret(password)));
        _ = await client.ReceiveAsync<UserRegisterAck>();
        await client.SendAsync(new UserLogin(client.NextSeq(), client.Now(), MsgType.UserLogin, username, "", client.BoxLoginSecret(password)));
        var login = await RequireCompletedAsync(client.ReceiveAsync<UserLoginAck>());
        Assert.True(login!.Ok);
        return client;
    }

    /// <summary>登录（即时路径）：应答不应挂起——有延迟档而无推进即超时判负（零感知断言）。</summary>
    private static async Task<T> RequireCompletedAsync<T>(Task<T?> task, int ms = 8000)
    {
        var done = await Task.WhenAny(task, Task.Delay(ms));
        Assert.True(ReferenceEquals(done, task), "应答挂起：无延迟路径不应等待");
        return await task ?? throw new IOException("无应答");
    }

    /// <summary>阶梯延迟期间的 0x21：FakeTimeProvider 50ms 步进推进放行（轮询防服务端未入延迟的竞态）。</summary>
    private async Task<UserLoginAck> LoginWithAdvanceAsync(TestPcpClient client, string username, string password)
    {
        await client.SendAsync(new UserLogin(client.NextSeq(), client.Now(), MsgType.UserLogin, username, "", client.BoxLoginSecret(password)));
        var recv = client.ReceiveAsync<UserLoginAck>();
        for (var i = 0; i < 400 && !recv.IsCompleted; i++)
        {
            _time.Advance(TimeSpan.FromMilliseconds(50));
            await Task.Delay(2);
        }
        return await recv ?? throw new IOException("登录无应答");
    }

    /// <summary>阶梯延迟期间的 0x23（同上推进模式）。</summary>
    private async Task<UserChangePasswordAck> ChangePasswordWithAdvanceAsync(
        TestPcpClient client, string oldPassword, string newPassword)
    {
        await client.SendAsync(new UserChangePassword(client.NextSeq(), client.Now(), MsgType.UserChangePassword, "", "", client.BoxLoginSecret(oldPassword), client.BoxLoginSecret(newPassword)));
        var recv = client.ReceiveAsync<UserChangePasswordAck>();
        for (var i = 0; i < 400 && !recv.IsCompleted; i++)
        {
            _time.Advance(TimeSpan.FromMilliseconds(50));
            await Task.Delay(2);
        }
        return await recv ?? throw new IOException("改密无应答");
    }

    private async Task<int> AuditCountAsync(string @event)
    {
        await using var db = CreateDb();
        return await db.AuditLogs.AsNoTracking().CountAsync(a => a.Event == @event);
    }

    [Fact]
    public async Task 登录阶梯递增_账户维成功复位_IP维滑窗衰减()
    {
        const string user = "throttle-a", pass = "secret-123";
        var client = await ConnectLoggedInAsync(user, pass);
        // 会话保持 normal（0x21 为主动类——passive 会被 2002 拒，02 §2.5；失败尝试在 normal 会话上发）

        // 第 1 次失败无延迟即时应答；第 2 次 500ms 档（推进放行）——延迟后仍是正常失败应答（不设专用码）
        await client.SendAsync(new UserLogin(client.NextSeq(), client.Now(), MsgType.UserLogin, user, "", client.BoxLoginSecret("wrong-1")));
        Assert.False((await RequireCompletedAsync(client.ReceiveAsync<UserLoginAck>()))!.Ok);
        Assert.False((await LoginWithAdvanceAsync(client, user, "wrong-2")).Ok);

        // 第 3 次正确口令：吃 1000ms 当前档仍成功（A-15 延迟期间正确登录同受档）——账户维复位
        Assert.True((await LoginWithAdvanceAsync(client, user, pass)).Ok);

        // 第 4 次正确口令：IP 维仍 2 次窗内计数（成功不清 IP 维）→ 仍 1000ms 档
        Assert.True((await LoginWithAdvanceAsync(client, user, pass)).Ok);

        // 窗衰减：901s > 900s 窗 → 双维归零，无推进即应答（正常用户零感知回归）
        _time.Advance(TimeSpan.FromSeconds(901));
        await client.SendAsync(new UserLogin(client.NextSeq(), client.Now(), MsgType.UserLogin, user, "", client.BoxLoginSecret(pass)));
        Assert.True((await RequireCompletedAsync(client.ReceiveAsync<UserLoginAck>()))!.Ok);

        Assert.Equal(2, await AuditCountAsync("login_failed"));
        // 阶跃审计：account/ip 两维各 fails=1,2 跨档 → 各 2 条（07 §11.3 ≤5 条/键）
        Assert.Equal(4, await AuditCountAsync("login_throttled"));
    }

    [Fact]
    public async Task 改密与登录同键共享_失败互抬延迟_成功同复位()
    {
        const string user = "throttle-b", pass = "secret-456";
        var client = await ConnectLoggedInAsync(user, pass);

        // 0x21 失败 1 次（acct=1/ip=1）
        await client.SendAsync(new UserLogin(client.NextSeq(), client.Now(), MsgType.UserLogin, user, "", client.BoxLoginSecret("wrong")));
        Assert.False((await RequireCompletedAsync(client.ReceiveAsync<UserLoginAck>()))!.Ok);

        // 0x23 错旧密码：账户维共享 0x21 失败 → 已上 500ms 档（推进放行）；Ack 仍正常失败语义
        Assert.False((await ChangePasswordWithAdvanceAsync(client, "wrong-old", "newpass-77")).Ok);

        // 0x23 正确旧密码：吃 1000ms 档成功——凭据成功复位账户维（07 §11.1 复位由账户维兑现）
        Assert.True((await ChangePasswordWithAdvanceAsync(client, pass, "newpass-77")).Ok);

        // 改密成功后 0x21：acct=0 但 ip=2 → 仍吃 1000ms 档（IP 维不清零）后新口令成功
        Assert.True((await LoginWithAdvanceAsync(client, user, "newpass-77")).Ok);

        Assert.Equal(1, await AuditCountAsync("login_failed"));
        Assert.Equal(1, await AuditCountAsync("password_change_failed"));
        // 阶跃：acct fails=1,2 + ip fails=1,2 → 4 条（0x23 两步各抬一档）
        Assert.Equal(4, await AuditCountAsync("login_throttled"));
    }
}
