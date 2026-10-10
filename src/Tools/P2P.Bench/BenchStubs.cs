// M4-05 基准替身件：StubNicManager（镜像 tests/P2P.IntegrationTests 的同名替身——该类内嵌于
// 测试文件不可跨工程引用，此处保持逐行为同构副本）+ 临时 SQLite 库工厂（Scenario 装配同模式）。
using System.Net;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using P2P.Client.Nic;
using P2P.Nic;
using P2P.Server.Data;

namespace P2P.Bench;

/// <summary>网卡替身（与 tests 侧 StubNicManager 同构）：Ensure 记录+恒在位健康。</summary>
internal sealed class StubNicManager : INicManager
{
    public List<IPAddress> Ensured { get; } = [];

#pragma warning disable CS0067 // 接口事件保留位
    public event Action<string>? Degraded;
#pragma warning restore CS0067

    public Task<NicHandle> EnsureAsync(IPAddress virtualIp, CancellationToken ct = default)
    {
        Ensured.Add(virtualIp);
        return Task.FromResult(new NicHandle("stub-0", virtualIp));
    }

    public Task RemoveAsync(CancellationToken ct = default) => Task.CompletedTask;

    public NicHealth CheckHealth(IPAddress expectedIp) => new(NicHealthState.Healthy, expectedIp);

    public Task<bool> RemoveLeftoverAsync(CancellationToken ct = default) => Task.FromResult(false);
}

/// <summary>临时 SQLite 文件库 + <see cref="IDbContextFactory{AppDbContext}"/>（每基准世界独立库，
/// ScenarioIntegrationTests.TestDatabase/StubFactory 同模式——共享连接串多上下文并发访问）。</summary>
internal sealed class BenchDatabase : IDisposable
{
    private readonly string _file;

    public BenchDatabase()
    {
        _file = Path.Combine(Path.GetTempPath(), $"p2p-bench-{Guid.NewGuid():N}.db");
        Factory = new DbFactory($"Data Source={_file}");
    }

    public IDbContextFactory<AppDbContext> Factory { get; }

    public void Dispose()
    {
        try { File.Delete(_file); }
        catch (IOException) { /* Windows 句柄延迟释放宽限 */ }
    }

    private sealed class DbFactory(string connectionString) : IDbContextFactory<AppDbContext>
    {
        public AppDbContext CreateDbContext() => new(
            new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connectionString).Options);
    }
}
