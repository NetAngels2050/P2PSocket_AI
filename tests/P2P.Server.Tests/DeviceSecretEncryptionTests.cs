using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using P2P.Core.Crypto;
using P2P.Server.Data;
using P2P.Server.Services;
using Xunit;

namespace P2P.Server.Tests;

/// <summary>
/// M5-13 静态数据加密 EF 集成面单测（SEC-83、07 §14.3，任务验收矩阵）：密文工厂写入 →
/// 直读 SQLite 断言 device_secret 非 61B 密文非明文；读取透明（明文/密文上下文同库共存=
/// 模型按 cipher 实例分缓存）；存量明文库迁移（改写+幂等）；密钥轮换重加密；不可解行跳过不阻断。
/// 生产形态 ServerDatabase.CreateFactory 直用（文件库）；迁移器经明文工厂裸读写（不经转换器）。
/// </summary>
public sealed class DeviceSecretEncryptionTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "p2p-enc-" + Guid.NewGuid().ToString("N"));

    private string DbPath => Path.Combine(_dir, "p2p.db");

    private static IDbContextFactory<AppDbContext> Factory(string path, DeviceSecretCipher? cipher = null)
        => ServerDatabase.CreateFactory(path, cipher);

    private static string HexKey() => Convert.ToHexString(RandomGenerator.Bytes(32)).ToLowerInvariant();

    /// <summary>直接构实体（与集成夹具 SeedDevice 同形；MacCode/RemoteCode 仅保证唯一）。</summary>
    private static Device NewDevice(byte[] secret) => new()
    {
        Id = Guid.NewGuid(),
        DeviceName = "enc-test",
        Os = "windows",
        ClientVersion = "0.1.0",
        MacCode = $"EN-{Guid.NewGuid():N}"[..16],
        RemoteCode = $"ER-{Guid.NewGuid():N}"[..10],
        VirtualIp = "100.64.0.2",
        StaticPubKey = new byte[65],
        DeviceSecret = secret,
        CreatedAt = DateTime.UtcNow,
    };

    [Fact]
    public void 写入经转换器_直读SQLite为61B密文_非明文()
    {
        var cipher = new DeviceSecretCipher(HexKey());
        var secret = RandomGenerator.Bytes(32);
        var factory = Factory(DbPath, cipher);
        using (var db = factory.CreateDbContext())
            DbInitializer.Initialize(db); // Migrate 走密文模型（converter 不改列型——无 pending-changes）
        using (var db = factory.CreateDbContext())
        {
            db.Devices.Add(NewDevice(secret));
            db.SaveChanges();
        }

        // 裸 ADO 直读（绕开 EF 转换器）：列值即密文
        using var con = new SqliteConnection($"Data Source={DbPath.Replace('\\', '/')}");
        con.Open();
        using var cmd = con.CreateCommand();
        cmd.CommandText = "SELECT device_secret FROM devices";
        var raw = (byte[])cmd.ExecuteScalar()!;
        Assert.Equal(61, raw.Length);
        Assert.Equal(cipher.CurrentKeyTag, raw[0]);
        Assert.False(raw.AsSpan(13, 32).SequenceEqual(secret)); // ct 段（1+12 起）≠ 明文
    }

    [Fact]
    public void 读取透明_明文上下文同库共存_模型分缓存()
    {
        var cipher = new DeviceSecretCipher(HexKey());
        var secret = RandomGenerator.Bytes(32);
        var encFactory = Factory(DbPath, cipher);
        using (var db = encFactory.CreateDbContext())
            DbInitializer.Initialize(db);
        using (var db = encFactory.CreateDbContext())
        {
            db.Devices.Add(NewDevice(secret));
            db.SaveChanges();
        }

        // 明文工厂（无 cipher）读同一库：模型缓存分离——读到 61B 原始密文（不互踩首个构建的模型）
        var plainFactory = Factory(DbPath);
        using (var db = plainFactory.CreateDbContext())
        {
            var raw = db.Devices.AsNoTracking().Single().DeviceSecret;
            Assert.Equal(61, raw.Length);
            Assert.Equal(cipher.CurrentKeyTag, raw[0]);
        }
        // 密文工厂读回：透明解密=32B 明文（读路径零改动）
        using (var db = encFactory.CreateDbContext())
            Assert.Equal(secret, db.Devices.AsNoTracking().Single().DeviceSecret);
    }

    [Fact]
    public void 存量明文库迁移_改写为密文_幂等()
    {
        var secret = RandomGenerator.Bytes(32);
        var plainFactory = Factory(DbPath); // 升级前：明文库
        using (var db = plainFactory.CreateDbContext())
        {
            DbInitializer.Initialize(db);
            db.Devices.Add(NewDevice(secret));
            db.SaveChanges();
        }

        var cipher = new DeviceSecretCipher(HexKey()); // 升级后带钥启动
        var (migrated, skipped) = DeviceSecretMigrator.Migrate(plainFactory, cipher);
        Assert.Equal((1, 0), (migrated, skipped));

        using (var db = plainFactory.CreateDbContext()) // 裸读：32B 明文行已改写 61B 密文
        {
            var raw = db.Devices.AsNoTracking().Single().DeviceSecret;
            Assert.Equal(61, raw.Length);
            Assert.Equal(cipher.CurrentKeyTag, raw[0]);
        }
        var encFactory = Factory(DbPath, cipher); // 凭据透明可验
        using (var db = encFactory.CreateDbContext())
            Assert.Equal(secret, db.Devices.AsNoTracking().Single().DeviceSecret);

        var (m2, s2) = DeviceSecretMigrator.Migrate(plainFactory, cipher); // 再迁移：61B 当前 tag 行不动
        Assert.Equal((0, 0), (m2, s2));
    }

    [Fact]
    public void 密钥轮换_prev密文重加密为当前钥()
    {
        var prevHex = HexKey();
        var secret = RandomGenerator.Bytes(32);
        // 旧钥时期：密文工厂写入 prev 钥密文行
        var prevCipher = new DeviceSecretCipher(prevHex);
        var encFactory = Factory(DbPath, prevCipher);
        using (var db = encFactory.CreateDbContext())
        {
            DbInitializer.Initialize(db);
            db.Devices.Add(NewDevice(secret));
            db.SaveChanges();
        }

        // 轮换启动（生产序=Program：明文工厂裸读写——不经值转换器，prev 密文行按裸值判定）
        var plainFactory = Factory(DbPath);
        var rotated = new DeviceSecretCipher(HexKey(), prevHex);
        var (migrated, skipped) = DeviceSecretMigrator.Migrate(plainFactory, rotated);
        Assert.Equal((1, 0), (migrated, skipped));

        using (var db = plainFactory.CreateDbContext()) // 轮换落库=当前钥 tag（prev 可移除）
        {
            var raw = db.Devices.AsNoTracking().Single().DeviceSecret;
            Assert.Equal(61, raw.Length);
            Assert.Equal(rotated.CurrentKeyTag, raw[0]);
        }
        var newFactory = Factory(DbPath, rotated);
        using (var db = newFactory.CreateDbContext())
            Assert.Equal(secret, db.Devices.AsNoTracking().Single().DeviceSecret);
    }

    [Fact]
    public void 迁移遇不可解行_跳过不阻断_行原样()
    {
        var cipher = new DeviceSecretCipher(HexKey());
        var garbage = RandomGenerator.Bytes(61);
        garbage[0] = (byte)(cipher.CurrentKeyTag ^ 0xFF); // 必非当前 tag（无 prev）→ 不可解路径
        var plainFactory = Factory(DbPath);
        using (var db = plainFactory.CreateDbContext())
        {
            DbInitializer.Initialize(db);
            db.Devices.Add(NewDevice(garbage));
            db.SaveChanges();
        }

        var (migrated, skipped) = DeviceSecretMigrator.Migrate(plainFactory, cipher); // 不抛
        Assert.Equal((0, 1), (migrated, skipped));
        using (var db = plainFactory.CreateDbContext())
            Assert.Equal(garbage, db.Devices.AsNoTracking().Single().DeviceSecret); // 原样保留（不动即不损坏）
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch (IOException) { /* Windows 句柄释放竞态：留待临时目录清理 */ }
    }
}
