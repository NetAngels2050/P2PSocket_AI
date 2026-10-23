using System.Net;
using System.Net.Sockets;
using Microsoft.EntityFrameworkCore;
using P2P.Server.Data;
using P2P.Server.Services;
using Xunit;

namespace P2P.Server.Tests;

/// <summary>
/// M5-10/SEC-64 控制端口并发闸（07 §12、03 §2.8 control_conn_max_per_ip/total）：
/// 单 IP/总量任一达限 accept 即关（EOF）、会话结束配额归还（释放回收）、
/// 两键 accept 时现读（热改收紧即时生效）、存量已建会话不受收紧回溯。
/// 裸 TCP 连接（不发 Hello——会话读循环静置等待，M5-08 黑名单用例同法）；
/// 存活断言=读静默超时（未被关）、被拒断言=读到 EOF。
/// </summary>
public sealed class ControlConnLimitTests : IAsyncLifetime
{
    private readonly TestDatabase _db = new();
    private readonly DeviceRegistry _registry = new();
    private readonly List<TcpClient> _clients = [];
    private ControlServer _server = null!;

    public Task InitializeAsync()
    {
        var factory = new StubFactory(CreateDb);
        using (var init = factory.CreateDbContext())
            DbInitializer.Initialize(init);
        _server = new ControlServer(factory, _registry, (_, _) => Task.CompletedTask);
        return _server.StartAsync(new IPEndPoint(IPAddress.Loopback, 0));
    }

    public async Task DisposeAsync()
    {
        foreach (var c in _clients) c.Dispose();
        await _server.DisposeAsync();
        _db.Dispose();
    }

    private AppDbContext CreateDb() => new(
        new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_db.DataSource).Options);

    /// <summary>改双键库值（accept 循环每次现读——写后下一连接即生效）。</summary>
    private void SetLimits(string perIp, string total)
    {
        using var db = CreateDb();
        db.ServerConfig.Single(c => c.Key == "control_conn_max_per_ip").Value = perIp;
        db.ServerConfig.Single(c => c.Key == "control_conn_max_total").Value = total;
        db.SaveChanges();
    }

    private async Task<TcpClient> ConnectAsync()
    {
        var client = new TcpClient();
        await client.ConnectAsync(_server.LocalEndPoint!);
        _clients.Add(client);
        return client;
    }

    /// <summary>读到 EOF=服务端已关（超限即关的观测点）。</summary>
    private static async Task<bool> ReadClosedAsync(TcpClient client, int timeoutMs = 3000)
    {
        var read = client.GetStream().ReadAsync(new byte[1], CancellationToken.None).AsTask();
        return await Task.WhenAny(read, Task.Delay(timeoutMs)) == read && await read == 0;
    }

    /// <summary>读静默超时=未被关=存活（M5-08 黑名单用例同法）。</summary>
    private static async Task<bool> IsAliveAsync(TcpClient client, int timeoutMs = 300)
    {
        var read = client.GetStream().ReadAsync(new byte[1], CancellationToken.None).AsTask();
        return await Task.WhenAny(read, Task.Delay(timeoutMs)) != read;
    }

    private async Task WaitSessionsAsync(int expected)
    {
        for (var i = 0; i < 150 && _server.Sessions.Count != expected; i++)
            await Task.Delay(20);
        Assert.Equal(expected, _server.Sessions.Count);
    }

    [Fact]
    public async Task 单IP超限即关_释放回收_存量不受影响()
    {
        SetLimits("2", "1024");

        var c1 = await ConnectAsync();
        var c2 = await ConnectAsync();
        await WaitSessionsAsync(2);
        Assert.True(await IsAliveAsync(c1)); // 存量存活
        Assert.True(await IsAliveAsync(c2));

        var c3 = await ConnectAsync();
        Assert.True(await ReadClosedAsync(c3)); // 第 3 条（同 IP）accept 即关 EOF
        Assert.Equal(2, _server.Sessions.Count); // 存量不受回溯

        c1.Dispose(); // 会话结束 → 配额归还（WatchAsync 先归还再移出）
        await WaitSessionsAsync(1);
        var c4 = await ConnectAsync();
        await WaitSessionsAsync(2); // 回收后同 IP 可再入
        Assert.True(await IsAliveAsync(c4));
    }

    [Fact]
    public async Task 总量超限即关()
    {
        SetLimits("64", "2"); // 单 IP 不设障，只测总闸

        var c1 = await ConnectAsync();
        var c2 = await ConnectAsync();
        await WaitSessionsAsync(2);

        var c3 = await ConnectAsync();
        Assert.True(await ReadClosedAsync(c3)); // 总量第 3 条拒
        Assert.Equal(2, _server.Sessions.Count);
        Assert.True(await IsAliveAsync(c1)); // 存量不受影响
    }

    [Fact]
    public async Task 热改收紧即时生效_存量不受回溯()
    {
        SetLimits("3", "1024");
        var c1 = await ConnectAsync();
        var c2 = await ConnectAsync();
        await WaitSessionsAsync(2);

        SetLimits("1", "1024"); // 热改收紧（accept 现读）
        var c3 = await ConnectAsync();
        Assert.True(await ReadClosedAsync(c3)); // 已有 2 ≥ 1：新连接拒
        await WaitSessionsAsync(2); // 存量两条不受回溯
        Assert.True(await IsAliveAsync(c1));
        Assert.True(await IsAliveAsync(c2));

        c2.Dispose();
        await WaitSessionsAsync(1);
        var c4 = await ConnectAsync();
        Assert.True(await ReadClosedAsync(c4)); // 剩 1 ≥ 1：收紧后新面仍满

        SetLimits("3", "1024"); // 放宽即恢复
        var c5 = await ConnectAsync();
        await WaitSessionsAsync(2);
        Assert.True(await IsAliveAsync(c5));
    }
}
