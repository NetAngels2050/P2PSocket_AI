using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using P2P.Server.Data;

namespace P2P.Server.Services;

/// <summary>宿主数据库装配（08 §5.1 database.path → SQLite；目录自动创建）。</summary>
public static class ServerDatabase
{
    /// <summary>cipher 在位时启用静态加密（SEC-83、07 §14.3）：device_secret 列级值转换器 +
    /// 模型缓存键工厂替换（加密/明文上下文同进程并存时按 cipher 实例分模型，防互踩）。</summary>
    public static IDbContextFactory<AppDbContext> CreateFactory(string path, DeviceSecretCipher? cipher = null)
    {
        var fullPath = Path.GetFullPath(path);
        var dir = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        return new SimpleFactory(BuildOptions($"Data Source={fullPath}", cipher), cipher);
    }

    /// <summary>测试缝：自定义连接串（集成夹具 TestDatabase.DataSource）直造工厂——
    /// cipher 装配/上下文注入同源（防 options 与 ctor cipher 脱钩的静默裸读误用）。</summary>
    public static IDbContextFactory<AppDbContext> CreateFactoryFromDataSource(string dataSource, DeviceSecretCipher? cipher = null)
        => new SimpleFactory(BuildOptions(dataSource, cipher), cipher);

    private static DbContextOptions<AppDbContext> BuildOptions(string dataSource, DeviceSecretCipher? cipher = null)
    {
        var ob = new DbContextOptionsBuilder<AppDbContext>().UseSqlite(dataSource);
        if (cipher is not null)
            ob.ReplaceService<IModelCacheKeyFactory, AppDbContextCacheKeyFactory>();
        return ob.Options;
    }

    private sealed class SimpleFactory(DbContextOptions<AppDbContext> options, DeviceSecretCipher? cipher) : IDbContextFactory<AppDbContext>
    {
        public AppDbContext CreateDbContext() => new(options, cipher);

        public Task<AppDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default)
            => Task.FromResult(CreateDbContext());
    }
}

/// <summary>模型缓存键含 cipher 实例（M5-13/SEC-83）：明文/密文上下文与不同钥实例互不共享模型。</summary>
public sealed class AppDbContextCacheKeyFactory : IModelCacheKeyFactory
{
    public object Create(DbContext context, bool designTime)
        => context is AppDbContext ctx
            ? (context.GetType(), ctx.Cipher, designTime)
            : (context.GetType(), designTime);
}
