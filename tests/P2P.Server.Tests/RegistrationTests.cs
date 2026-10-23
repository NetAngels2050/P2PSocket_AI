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
/// 注册族集成测试（02 §2.4 0x10/0x12；完成判定：恢复保留 deviceId/远程码/分组、在线 4004、离线判定 30s）。
/// </summary>
public sealed class RegistrationTests : IAsyncLifetime
{
    private readonly TestDatabase _db = new();
    private readonly DeviceRegistry _registry = new();
    private readonly List<TestPcpClient> _clients = [];
    private ControlServer _server = null!;
    private RegistrationService _registration = null!;
    private SignalingCoordinator _signaling = null!;
    private RelayService _relay = null!;
    private FakeTimeProvider _time = null!;
    private RegistrationGuard _guard = null!;
    private RegistrationMetrics _metrics = null!;

    public Task InitializeAsync()
    {
        var factory = new StubFactory(CreateDb);
        using var init = factory.CreateDbContext();
        DbInitializer.Initialize(init);
        _time = new FakeTimeProvider(DateTimeOffset.UtcNow);

        var audit = new AuditLogger(factory, _time);
        _guard = new RegistrationGuard(new RegistrationGuardOptions(), _time); // 闸②：缺省 10 次/h/IP
        _metrics = new RegistrationMetrics(_time); // M5-07 注册风暴钩子（AlertPusher 消费面）
        _registration = new RegistrationService(factory, _registry, audit, _time, guard: _guard,
            metrics: _metrics);
        _signaling = new SignalingCoordinator(factory, _registry, new Authorizer(factory), audit, _time);
        _relay = new RelayService(factory, _registry, _signaling.ResolveRelayPeers, time: _time);
        var router = new ControlMessageRouter(_registration, new UserService(factory, audit, _time),
            new GroupService(factory, _registry, audit, time: _time), _signaling,
            new MappingService(factory, audit), _relay, new StatsService(factory, audit), audit);
        _server = new ControlServer(factory, _registry, router.DispatchAsync, time: _time);
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

    private async Task<TestPcpClient> ConnectAsync()
    {
        var client = await TestPcpClient.ConnectAsync(_server.LocalEndPoint!);
        client.Time = _time; // ts 校验与服务端假时钟对齐（M5-02 频控测试推进 1h 后仍可用）
        _clients.Add(client);
        return client;
    }

    /// <summary>走完整注册链路（未签名 Register → RegisterAck），解 ECIES 转签名会话。</summary>
    private async Task<(TestPcpClient Client, EcKeyPair Key, RegisterAck Ack, byte[] Secret)> RegisterAsync(
        string macCode, string hostname = "host-x")
    {
        var client = await ConnectAsync();
        var helloAck = await client.HelloAsync(deviceId: null);
        Assert.Equal(HelloStatus.NeedRegister, helloAck.Status);

        var key = EcKeyPair.Generate();
        await client.SendAsync(new Register(client.NextSeq(), client.Now(), MsgType.Register,
            macCode, hostname, "windows", "0.1.0", key.ExportPublicKey(), null, null, null), sign: false);
        var ack = await client.ReceiveAsync<RegisterAck>() ?? throw new IOException("注册无应答");

        var secret = Ecies.Decrypt(key, ack.DeviceSecretBox);
        client.EstablishWithSecret(secret); // RegisterAck 未签名；自此双向签名（02 §2.2）
        return (client, key, ack, secret);
    }

    private static async Task WaitForAsync(Func<bool> condition, string what, int timeoutMs = 5000)
    {
        var deadline = Environment.TickCount64 + timeoutMs;
        while (Environment.TickCount64 < deadline)
        {
            if (condition()) return;
            await Task.Delay(20);
        }
        Assert.True(condition(), $"等待超时：{what}");
    }

    // ── 0x10 新建注册 ──────────────────────────────────────────────────

    [Fact]
    public async Task Register_NewDevice_CreatesWithDefaults()
    {
        var (client, _, ack, secret) = await RegisterAsync("P2P-AABBCCDDEE01");

        Assert.NotEqual(Guid.Empty, ack.DeviceId);
        Assert.Equal(32, secret.Length);                       // ECIES 可解出 32B deviceSecret
        Assert.Matches("^[0-9abc]{6}$", ack.RemoteCode);       // 6 位 0-9+abc（D18/OQ-8）
        Assert.Equal(RegistrationService.VirtualIp, ack.VirtualIp); // 固定 .2（OQ-13）
        var groupName = ack.Groups.Single(g => g.GroupName == DbInitializer.DefaultGroupName);
        Assert.NotEqual(Guid.Empty, groupName.GroupId);

        // 会话已建立：签名心跳有应答；registry 在线
        Assert.True(_registry.IsOnline(ack.DeviceId));
        await client.SendAsync(new Heartbeat(client.NextSeq(), client.Now(), MsgType.Heartbeat));
        var hbAck = await client.ReceiveAsync<HeartbeatAck>();
        Assert.NotNull(hbAck);

        // 落库 + 审计
        await using var db = CreateDb();
        var device = await db.Devices.AsNoTracking().SingleAsync(d => d.Id == ack.DeviceId);
        Assert.Equal("host-x", device.DeviceName);
        Assert.Equal("P2P-AABBCCDDEE01", device.MacCode);
        Assert.True(await db.GroupMembers.AnyAsync(m => m.DeviceId == ack.DeviceId));
        Assert.True(await db.WaitAuditAsync(a => a.Event == "register" && a.DeviceId == ack.DeviceId));

        // M5-07 注册风暴钩子：成功注册按源 IP 计数（本夹具源=127.0.0.1）
        var snap = _metrics.SnapshotIpWindow(300);
        Assert.Equal(1, snap.Sum(s => s.Count));
        Assert.Contains(snap, s => s.Ip == "127.0.0.1");
    }

    // ── 0x10 覆盖式恢复（OQ-14）───────────────────────────────────────

    [Fact]
    public async Task Register_MacCodeOfflineHit_RecoversIdentity()
    {
        var (first, _, firstAck, firstSecret) = await RegisterAsync("P2P-RECOVER0001");
        var deviceId = firstAck.DeviceId;
        var mappingId = Guid.NewGuid();

        // 存量映射 + 额外分组归属（恢复后不失效）
        await using (var db = CreateDb())
        {
            db.Mappings.Add(new Mapping
            {
                Id = mappingId,
                OwnerDeviceId = deviceId,
                Name = "存量",
                LocalPort = 8080,
                Proto = "tcp",
                TargetDeviceId = deviceId,
                TargetAddr = "self",
                TargetPort = 80,
                Enabled = true,
                CreatedAt = DateTime.UtcNow,
            });
            await db.SaveChangesAsync();
        }
        await first.DisposeAsync(); // 原设备离线
        await WaitForAsync(() => !_registry.IsOnline(deviceId), "原会话注销");

        var (recovered, _, ack, newSecret) = await RegisterAsync("P2P-RECOVER0001");

        Assert.Equal(deviceId, ack.DeviceId);                  // 保留 deviceId
        Assert.Equal(firstAck.RemoteCode, ack.RemoteCode);     // 保留远程码
        Assert.NotEqual(firstSecret, newSecret);               // deviceSecret 重签
        Assert.Equal(RegistrationService.VirtualIp, ack.VirtualIp);
        Assert.Contains(ack.Groups, g => g.GroupName == DbInitializer.DefaultGroupName); // 分组保留

        await using var db2 = CreateDb();
        Assert.True(await db2.Mappings.AnyAsync(m => m.Id == mappingId), "存量映射不失效");
        Assert.True(await db2.WaitAuditAsync(a => a.Event == "register_recover" && a.DeviceId == deviceId));
        _ = recovered;
    }

    [Fact]
    public async Task Register_MacCodeOnlineHit_Gets4004()
    {
        var (online, _, ack, _) = await RegisterAsync("P2P-ONLINE00001");
        Assert.True(_registry.IsOnline(ack.DeviceId)); // 原设备在线

        // 另一连接同 macCode 抢注 → 4004 + 断连（防伪造 MAC，OQ-14）
        var rival = await ConnectAsync();
        await rival.HelloAsync(deviceId: null);
        var key = EcKeyPair.Generate();
        await rival.SendAsync(new Register(rival.NextSeq(), rival.Now(), MsgType.Register,
            "P2P-ONLINE00001", "rival", "windows", "0.1.0", key.ExportPublicKey(), null, null, null), sign: false);
        var error = await rival.ReceiveAsync<ErrorMessage>();
        Assert.NotNull(error);
        Assert.Equal(ErrorCode.DeviceActive, error!.Code);
        Assert.True(await rival.WaitClosedAsync(), "4004 后应断连");

        Assert.True(_registry.IsOnline(ack.DeviceId), "原设备不受影响");
        _ = online;
    }

    // ── M5-15 输入长度上限（SEC-85、07 §14.5）────────────────────────

    [Fact]
    public async Task Register_Hostname_OverLimitOrBlank_Gets1001_StaysRetriable()
    {
        var client = await ConnectAsync();
        await client.HelloAsync(deviceId: null);
        var key = EcKeyPair.Generate();

        // 65 字符超上限 / 空白 / 空串 → 1001 hostname_invalid（0x10 无 Ok 载体）
        foreach (var bad in new[] { new string('名', 65), "   ", "" })
        {
            await client.SendAsync(new Register(client.NextSeq(), client.Now(), MsgType.Register,
                "P2P-HOST000001", bad, "windows", "0.1.0", key.ExportPublicKey(), null, null, null), sign: false);
            var error = await client.ReceiveAsync<ErrorMessage>();
            Assert.NotNull(error);
            Assert.Equal(ErrorCode.BadRequest, error!.Code);
            Assert.Equal("hostname_invalid", error.HttpLikeMsg);
        }

        // 拒绝不断连：同连接换合法 Hostname 立即成功（停留 NeedRegister 可重试，07 §14.5）
        Assert.False(await client.WaitClosedAsync(), "hostname_invalid 不应断连");
        await client.SendAsync(new Register(client.NextSeq(), client.Now(), MsgType.Register,
            "P2P-HOST000001", "  合法名  ", "windows", "0.1.0", key.ExportPublicKey(), null, null, null), sign: false);
        var ack = await client.ReceiveAsync<RegisterAck>() ?? throw new IOException("注册无应答");

        // trim 口径：落库去两端空白
        await using var db = CreateDb();
        var device = await db.Devices.AsNoTracking().SingleAsync(d => d.MacCode == "P2P-HOST000001");
        Assert.Equal("合法名", device.DeviceName);
    }

    [Fact]
    public async Task Register_Hostname_Boundary64_Passes()
    {
        var (_, _, ack, _) = await RegisterAsync("P2P-HOST000002", new string('名', 64));
        await using var db = CreateDb();
        var device = await db.Devices.AsNoTracking().SingleAsync(d => d.Id == ack.DeviceId);
        Assert.Equal(new string('名', 64), device.DeviceName);
    }

    // ── M5-03 注册入组遵循默认分组策略（SEC-62、07 §5.2）─────────────

    [Fact]
    public async Task Register_DefaultGroupApproval_PendingAndInvisibleUntilApproved()
    {
        // 策略切换（管理页 PUT 同值落行——行值即时生效）
        await using (var db = CreateDb())
            await db.Groups.Where(g => g.IsDefault)
                .ExecuteUpdateAsync(s => s.SetProperty(g => g.JoinPolicy, "approval"));

        var (_, _, ack, _) = await RegisterAsync("P2P-APPROVAL001");
        Assert.Empty(ack.Groups); // 仅 approved 行 → 空组=待审（向导呈现「待审批」的数据面）

        await using var db2 = CreateDb();
        Assert.False(await db2.GroupMembers.AnyAsync(m => m.DeviceId == ack.DeviceId), "未批准前组内不可见");
        var request = await db2.JoinRequests.AsNoTracking()
            .SingleAsync(r => r.DeviceId == ack.DeviceId && r.Status == "pending");
        Assert.True(await db2.WaitAuditAsync(a => a.Event == "group_join_request"
            && a.DeviceId == ack.DeviceId && a.Detail!.Contains("register")), "待审入审计（source=register）");

        // 批准走既有共享核（0x53/管理页同执行链）：入组后可见
        var groups = new GroupService(new StubFactory(CreateDb), _registry,
            new AuditLogger(new StubFactory(CreateDb), _time), time: _time);
        Assert.True(await groups.DecideJoinRequestAsync(request.Id, approve: true));

        await using var db3 = CreateDb();
        Assert.True(await db3.GroupMembers.AnyAsync(m => m.DeviceId == ack.DeviceId && m.Approved), "批准后可见");
        // 批准审计行 DeviceId=审批者（actor）——被批准设备在 detail（既有共享核口径）
        Assert.True(await db3.WaitAuditAsync(a => a.Event == "group_join_approve"
            && a.Detail!.Contains(ack.DeviceId.ToString())));
    }

    // ── M5-02 注册准入三重闸门（SEC-61、07 §5.1）──────────────────────

    /// <summary>直写 server_config（闸门参数改值——测试不走红 Web PUT）。</summary>
    private async Task SetConfigAsync(string key, string value)
    {
        await using var db = CreateDb();
        var row = await db.ServerConfig.SingleAsync(c => c.Key == key);
        row.Value = value;
        await db.SaveChangesAsync();
    }

    /// <summary>NeedRegister 态连接上发未签名 Register，收 0x7E 预期错误。</summary>
    private static async Task<ErrorMessage> SendRegisterExpectErrorAsync(TestPcpClient client, string macCode)
    {
        var key = EcKeyPair.Generate();
        await client.SendAsync(new Register(client.NextSeq(), client.Now(), MsgType.Register,
            macCode, "host-x", "windows", "0.1.0", key.ExportPublicKey(), null, null, null), sign: false);
        return await client.ReceiveAsync<ErrorMessage>() ?? throw new IOException("预期错误应答");
    }

    [Fact]
    public async Task Gate1_关闸拒4006审计_同连接开闸重试成功()
    {
        await SetConfigAsync("device_registration_open", "0");
        var client = await ConnectAsync();
        var helloAck = await client.HelloAsync(deviceId: null);
        Assert.Equal(HelloStatus.NeedRegister, helloAck.Status);

        var error = await SendRegisterExpectErrorAsync(client, "P2P-GATE100001");
        Assert.Equal(ErrorCode.RegistrationDenied, error.Code);
        Assert.Equal("registration_denied", error.HttpLikeMsg); // 三闸统一文案不区分拒因

        await using (var db = CreateDb())
            Assert.True(await db.WaitAuditAsync(
                a => a.Event == "register_deny" && a.Detail!.Contains("\"switch\"")));

        // 拒绝后停留 NeedRegister 不断连：开闸（现读）后同连接重试即成功
        await SetConfigAsync("device_registration_open", "1");
        await client.SendAsync(new Register(client.NextSeq(), client.Now(), MsgType.Register,
            "P2P-GATE100001", "host-x", "windows", "0.1.0", EcKeyPair.Generate().ExportPublicKey(),
            null, null, null), sign: false);
        var ack = await client.ReceiveAsync<RegisterAck>() ?? throw new IOException("开闸后注册无应答");
        Assert.NotEqual(Guid.Empty, ack.DeviceId);
    }

    [Fact]
    public async Task Gate3_超上限拒新增_覆盖式恢复查而不拦()
    {
        await SetConfigAsync("max_devices", "1");
        var (first, _, firstAck, _) = await RegisterAsync("P2P-QUOTA00001"); // 第 1 台：count 0→1 放行

        var client = await ConnectAsync();
        await client.HelloAsync(deviceId: null);
        var error = await SendRegisterExpectErrorAsync(client, "P2P-QUOTA00002");
        Assert.Equal(ErrorCode.RegistrationDenied, error.Code);
        await using (var db = CreateDb())
            Assert.True(await db.WaitAuditAsync(
                a => a.Event == "register_deny" && a.Detail!.Contains("\"quota\"")));

        // 查而不拦：达上限后离线设备覆盖式恢复放行（不新增行，07 §5.1）
        await first.DisposeAsync();
        await WaitForAsync(() => !_registry.IsOnline(firstAck.DeviceId), "原会话注销");
        var (_, _, recovered, _) = await RegisterAsync("P2P-QUOTA00001");
        Assert.Equal(firstAck.DeviceId, recovered.DeviceId);
    }

    [Fact]
    public async Task Gate2_同IP超桶拒_推进1h补币恢复()
    {
        for (var i = 0; i < 10; i++) // 容量 10 初始满桶（缺省 register_rate_per_ip=10）
            await RegisterAsync($"P2P-RATE0000{i}");

        var client = await ConnectAsync();
        await client.HelloAsync(deviceId: null);
        var error = await SendRegisterExpectErrorAsync(client, "P2P-RATE00010");
        Assert.Equal(ErrorCode.RegistrationDenied, error.Code);
        await using (var db = CreateDb())
            Assert.True(await db.WaitAuditAsync(
                a => a.Event == "register_deny" && a.Detail!.Contains("\"rate\"")));

        // 拒绝不断连 + FakeTime 推进 1h 补满桶 → 同连接重试成功
        _time.Advance(TimeSpan.FromHours(1));
        await client.SendAsync(new Register(client.NextSeq(), client.Now(), MsgType.Register,
            "P2P-RATE00010", "host-x", "windows", "0.1.0", EcKeyPair.Generate().ExportPublicKey(),
            null, null, null), sign: false);
        var ack = await client.ReceiveAsync<RegisterAck>() ?? throw new IOException("补币后注册无应答");
        Assert.NotEqual(Guid.Empty, ack.DeviceId);
    }

    // ── 0x12 解绑 ─────────────────────────────────────────────────────

    [Fact]
    public async Task Unbind_Established_DeletesDeviceAndCleansUp()
    {
        var (client, _, ack, _) = await RegisterAsync("P2P-UNBIND00001");
        Assert.True(_registry.IsOnline(ack.DeviceId));

        await client.SendAsync(new UnbindMe(client.NextSeq(), client.Now(), MsgType.UnbindMe));
        Assert.True(await client.WaitClosedAsync(), "解绑后应断连");

        await WaitForAsync(() => !_registry.IsOnline(ack.DeviceId), "会话注销");
        await using var db = CreateDb();
        Assert.False(await db.Devices.AnyAsync(d => d.Id == ack.DeviceId));
        Assert.False(await db.GroupMembers.AnyAsync(m => m.DeviceId == ack.DeviceId));
        Assert.True(await db.WaitAuditAsync(a => a.Event == "unbind" && a.DeviceId == ack.DeviceId));
    }

    // ── 心跳超时离线判定（FR-S-104，30s 可配）─────────────────────────

    [Fact]
    public async Task PresenceMonitor_NoHeartbeatFor30s_MarksOfflineAndPersists()
    {
        var factory = new StubFactory(CreateDb);
        await using var monitor = new PresenceMonitor(_registry, factory,
            timeout: TimeSpan.FromSeconds(30), period: TimeSpan.FromSeconds(1), time: _time);

        var (client, _, ack, _) = await RegisterAsync("P2P-PRESENCE001");
        var deviceId = ack.DeviceId;
        await client.SendAsync(new Heartbeat(client.NextSeq(), client.Now(), MsgType.Heartbeat));
        var hb = await client.ReceiveAsync<HeartbeatAck>();
        Assert.NotNull(hb); // 心跳刷新 LastSeen

        _time.Advance(TimeSpan.FromSeconds(31)); // 无心跳 31s > 30s
        Assert.True(await client.WaitClosedAsync(), "超时应断连");
        await WaitForAsync(() => !_registry.IsOnline(deviceId), "registry 移除");

        await using var db = CreateDb();
        var device = await db.Devices.AsNoTracking().SingleAsync(d => d.Id == deviceId);
        Assert.NotNull(device.LastSeenAt); // last_seen_at 落库（05 §5）
    }

    [Fact]
    public async Task PresenceMonitor_RegularHeartbeat_StaysOnline()
    {
        var factory = new StubFactory(CreateDb);
        await using var monitor = new PresenceMonitor(_registry, factory,
            timeout: TimeSpan.FromSeconds(30), period: TimeSpan.FromSeconds(1), time: _time);

        var (client, _, ack, _) = await RegisterAsync("P2P-KEEPALIVE01");
        // 每 10s 心跳：累计 30s 不触发离线（判定按"最近心跳距今"）
        for (var i = 0; i < 3; i++)
        {
            _time.Advance(TimeSpan.FromSeconds(10));
            await client.SendAsync(new Heartbeat(client.NextSeq(), client.Now(), MsgType.Heartbeat));
            var hb = await client.ReceiveAsync<HeartbeatAck>();
            Assert.NotNull(hb);
        }
        Assert.True(_registry.IsOnline(ack.DeviceId), "持续心跳应保持在线");
    }
}
