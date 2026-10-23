using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Time.Testing;
using P2P.Core.Crypto;
using P2P.Core.Stun;
using P2P.Server.Data;
using P2P.Server.Services;
using Xunit;

namespace P2P.Server.Tests;

/// <summary>
/// M5-08 IP 黑名单（SEC-73、FR-S-828、07 §13.3）单测——完成判定对应：
/// 存储语义（manual 永久/覆盖升级/auto 过期自愈/刷新不重复入列/持久化重启恢复）+
/// 四面各自命中拒与放行（控制 accept 即关/STUN UDP 静默+TCP 关/中继 UDP JOIN 前拦/
/// Web 面在 SecurityApiTests 走 HTTP 全链）+ per-面命中计数器。
/// 四面夹具皆真 socket（FakeTime 驱动存储语义）。
/// </summary>
public sealed class BlacklistStoreTests : IAsyncLifetime
{
    private readonly TestDatabase _db = new();
    private readonly FakeTimeProvider _time = new(DateTimeOffset.Parse("2026-10-23T00:00:00Z"));
    private StubFactory _factory = null!;
    private BlacklistStore _store = null!;

    public Task InitializeAsync()
    {
        _factory = new StubFactory(CreateDb);
        using (var init = _factory.CreateDbContext())
            DbInitializer.Initialize(init);
        _store = new BlacklistStore(_factory, _time);
        return Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        await _store.DisposeAsync();
        _db.Dispose();
    }

    private AppDbContext CreateDb() => new(
        new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_db.DataSource).Options);

    private async Task<JsonElement> ReadHiddenRowAsync()
    {
        await using var db = CreateDb();
        var row = await db.ServerConfig.AsNoTracking().SingleAsync(c => c.Key == BlacklistStore.ConfigKey);
        return JsonDocument.Parse(row.Value).RootElement;
    }

    // ── 存储语义（07 §13.3 两层/条目生命周期）─────────────────────────

    [Fact]
    public async Task 手动加黑_永久条目_解封即删行()
    {
        await _store.BlockManualAsync("203.0.113.7", "扫描探测");
        Assert.True(_store.IsBlocked("203.0.113.7"));
        var entry = Assert.Single(_store.Snapshot());
        Assert.Equal(BlacklistStore.SourceManual, entry.Source);
        Assert.Null(entry.ExpiresAtUtc); // manual 永久

        Assert.True(await _store.RemoveAsync("203.0.113.7"));
        Assert.False(_store.IsBlocked("203.0.113.7"));
        Assert.Empty(_store.Snapshot());
        Assert.Equal(0, (await ReadHiddenRowAsync()).GetArrayLength()); // 写穿持久同步
    }

    [Fact]
    public async Task 自动条目_过期自愈_惰性判定与清扫双路()
    {
        Assert.True(await _store.AddAutoAsync("198.51.100.9", 45));
        Assert.True(_store.IsBlocked("198.51.100.9"));

        _time.Advance(TimeSpan.FromSeconds(46));
        Assert.False(_store.IsBlocked("198.51.100.9")); // 查询点惰性判定（不等清扫即拒答）
        Assert.Empty(_store.Snapshot());

        // 30s 清扫兜底：内存行移除+写穿持久清零（清扫回调在 fake 计时器推进点唤醒，
        // 其内异步持久化需真实让步收尾——单次 Advance 后续体可能晚于整段推进执行）
        for (var i = 0; i < 50 && (await ReadHiddenRowAsync()).GetArrayLength() > 0; i++)
        {
            _time.Advance(TimeSpan.FromSeconds(1)); // 唤醒清扫节拍
            await Task.Delay(10);
        }
        Assert.Equal(0, (await ReadHiddenRowAsync()).GetArrayLength()); // 持久层同步不留死行
    }

    [Fact]
    public async Task 手动覆盖同IP_auto_升级永久()
    {
        Assert.True(await _store.AddAutoAsync("203.0.113.7", 60));
        await _store.BlockManualAsync("203.0.113.7", "人工定性");

        var entry = Assert.Single(_store.Snapshot());
        Assert.Equal(BlacklistStore.SourceManual, entry.Source);
        Assert.Null(entry.ExpiresAtUtc);

        _time.Advance(TimeSpan.FromHours(2)); // 原 auto 到期时刻过后仍封——已升级永久
        Assert.True(_store.IsBlocked("203.0.113.7"));
    }

    [Fact]
    public async Task AddAuto_manual优先_不改写永久条目()
    {
        await _store.BlockManualAsync("203.0.113.7", "人工定性");
        Assert.False(await _store.AddAutoAsync("203.0.113.7", 60)); // 被压制：非新入列

        var entry = Assert.Single(_store.Snapshot());
        Assert.Equal(BlacklistStore.SourceManual, entry.Source);
        Assert.Null(entry.ExpiresAtUtc);
    }

    [Fact]
    public async Task AddAuto_未过期auto刷新到期_不重复入列()
    {
        Assert.True(await _store.AddAutoAsync("198.51.100.9", 60));
        var first = Assert.Single(_store.Snapshot());

        _time.Advance(TimeSpan.FromSeconds(30));
        Assert.False(await _store.AddAutoAsync("198.51.100.9", 60)); // 刷新（延长）非新入列

        var refreshed = Assert.Single(_store.Snapshot());
        Assert.Equal(first.CreatedAtUtc, refreshed.CreatedAtUtc); // 首封时刻保留
        Assert.Equal(_time.GetLocalNow().UtcDateTime.AddSeconds(60),
            refreshed.ExpiresAtUtc!.Value, TimeSpan.FromSeconds(1)); // 到期顺延
    }

    [Fact]
    public async Task 持久化_重启恢复()
    {
        await _store.BlockManualAsync("203.0.113.7", "跨重启");
        Assert.True(await _store.AddAutoAsync("198.51.100.9", 3600));

        await _store.DisposeAsync();
        await using var revived = new BlacklistStore(_factory, _time); // 同库新实例=重启语义

        Assert.True(revived.IsBlocked("203.0.113.7"));
        Assert.True(revived.IsBlocked("198.51.100.9"));
        var manual = revived.Snapshot().Single(e => e.Ip == "203.0.113.7");
        Assert.Equal(BlacklistStore.SourceManual, manual.Source);
        Assert.Equal("跨重启", manual.Reason);
        var auto = revived.Snapshot().Single(e => e.Ip == "198.51.100.9");
        Assert.Equal(BlacklistStore.SourceAuto, auto.Source);
        Assert.NotNull(auto.ExpiresAtUtc);
    }

    [Fact]
    public void 命中计数器_per面独立()
    {
        _store.CountHit(BlacklistStore.FaceControl);
        _store.CountHit(BlacklistStore.FaceControl);
        _store.CountHit(BlacklistStore.FaceWeb);
        var hits = _store.HitSnapshot();
        Assert.Equal(2, hits[BlacklistStore.FaceControl]);
        Assert.Equal(1, hits[BlacklistStore.FaceWeb]);
        Assert.False(hits.ContainsKey(BlacklistStore.FaceStun));
    }

    // ── 控制面（accept 后立即关闭——07 §13.3 四面表）──────────────────

    [Fact]
    public async Task 控制面_被封IP_accept即关_放行连接存活()
    {
        await _store.BlockManualAsync("127.0.0.1", null);
        var registry = new DeviceRegistry();
        await using var server = new ControlServer(_factory, registry,
            (_, _) => Task.CompletedTask, time: _time, blacklist: _store);
        await server.StartAsync(new IPEndPoint(IPAddress.Loopback, 0));

        // 被封：连接建立后服务端立即关闭（读到 EOF）+ 控制面计数
        using (var blocked = new TcpClient())
        {
            await blocked.ConnectAsync(server.LocalEndPoint!);
            using var stream = blocked.GetStream();
            var buffer = new byte[16];
            var read = await stream.ReadAsync(buffer);
            Assert.Equal(0, read); // 服务端关闭=EOF
        }
        Assert.Equal(1, _store.HitSnapshot()[BlacklistStore.FaceControl]);

        // 放行：解封后连接不被立即关（会话等 Hello，读阻塞超时=连接存活）
        Assert.True(await _store.RemoveAsync("127.0.0.1"));
        using (var allowed = new TcpClient())
        {
            await allowed.ConnectAsync(server.LocalEndPoint!);
            using var stream = allowed.GetStream();
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => stream.ReadAsync(new byte[16], cts.Token).AsTask()); // 未被关：读等待而非 EOF
        }
        Assert.Equal(1, _store.HitSnapshot()[BlacklistStore.FaceControl]); // 未新增
    }

    // ── STUN 面（UDP 到达先于四道闸静默丢弃；TCP accept 即关）────────

    private static byte[] BindingWire() => StunCodec.BuildBindingRequest(
        StunCodec.NewTransactionId(), Guid.NewGuid(), RandomGenerator.Bytes(32),
        (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), RandomGenerator.Bytes(16));

    [Fact]
    public async Task STUN面_UDP静默_TCP即关_解封即恢复()
    {
        await using var stun = new StunService(_factory, requireAuth: false, _time, blacklist: _store);
        await stun.StartAsync(0, 0);
        await _store.BlockManualAsync("127.0.0.1", null);

        using var udp = new UdpClient(AddressFamily.InterNetwork);
        udp.Connect(IPAddress.Loopback, stun.Port);
        await udp.SendAsync(BindingWire());
        Assert.Null(await ReceiveOrNullAsync(udp)); // 静默丢弃（无响应）

        using (var tcp = new TcpClient())
        {
            await tcp.ConnectAsync(IPAddress.Loopback, stun.TcpPort);
            using var stream = tcp.GetStream();
            Assert.Equal(0, await stream.ReadAsync(new byte[32])); // accept 即关
        }
        Assert.Equal(2, _store.HitSnapshot()[BlacklistStore.FaceStun]); // UDP+TCP 各计一次

        // 解封即恢复：UDP Binding 正常回包（requireAuth=false 跳过认证闸）
        Assert.True(await _store.RemoveAsync("127.0.0.1"));
        await udp.SendAsync(BindingWire());
        Assert.NotNull(await ReceiveOrNullAsync(udp));
        Assert.Equal(2, _store.HitSnapshot()[BlacklistStore.FaceStun]);
    }

    // ── 中继面（UDP JOIN 解析前拦；TCP accept 首帧 JOIN 前拦）────────

    [Fact]
    public async Task 中继面_UDP到达与TCP_accept前拦_解封不拦()
    {
        await using var relay = new RelayService(_factory, new DeviceRegistry(), time: _time,
            blacklist: _store);
        await relay.StartAsync(0, 0);
        await _store.BlockManualAsync("127.0.0.1", null);

        var join = new byte[9];
        join[0] = 0x01; // RELAY_JOIN 前缀（未知 sid——命中计数是判别面：黑名单先于表查找）
        BinaryPrimitives.WriteUInt64LittleEndian(join.AsSpan(1), 0x1122334455667788);

        using (var udp = new UdpClient(AddressFamily.InterNetwork))
        {
            udp.Connect(IPAddress.Loopback, relay.UdpEndpoint!.Port);
            await udp.SendAsync(join);
            Assert.Null(await ReceiveOrNullAsync(udp)); // 静默丢弃
        }
        using (var tcp = new TcpClient())
        {
            // 服务端绑 0.0.0.0（TcpEndpoint 为 Any）：回环寻址取端口派生（RelayServiceTests 同注）
            await tcp.ConnectAsync(new IPEndPoint(IPAddress.Loopback, relay.TcpEndpoint!.Port));
            using var stream = tcp.GetStream();
            Assert.Equal(0, await stream.ReadAsync(new byte[32])); // 首帧 JOIN 前关闭
        }
        Assert.Equal(2, _store.HitSnapshot()[BlacklistStore.FaceRelay]);

        // 解封后同包不再计入（JOIN 未知 sid 本就静默——以计数不增证闸放行）
        Assert.True(await _store.RemoveAsync("127.0.0.1"));
        using (var udp = new UdpClient(AddressFamily.InterNetwork))
        {
            udp.Connect(IPAddress.Loopback, relay.UdpEndpoint!.Port);
            await udp.SendAsync(join);
            Assert.Null(await ReceiveOrNullAsync(udp));
        }
        Assert.Equal(2, _store.HitSnapshot()[BlacklistStore.FaceRelay]);
    }

    private static async Task<UdpReceiveResult?> ReceiveOrNullAsync(UdpClient client, int timeoutMs = 500)
    {
        using var cts = new CancellationTokenSource(timeoutMs);
        try { return await client.ReceiveAsync(cts.Token); }
        catch (OperationCanceledException) { return null; }
    }
}
