using Microsoft.EntityFrameworkCore;
using Serilog;

namespace P2P.Server.Data;

/// <summary>
/// 存量库静态加密迁移（SEC-83、07 §14.3）：masterKey 在位时于启动早初始化后执行——
/// ① 32B 明文行 → 加密改写；② keyTag=prev 的 61B 密文行 → prev 解密+当前钥重加密（轮换）；
/// ③ keyTag=当前钥的 61B 行 → 不动（幂等：不因每次启动重掷 nonce）；
/// ④ 其余（不可解/异形）→ ERROR 跳过不阻断（与「缺钥不阻断」口径对齐，07 §14.3）。
/// 经明文工厂裸读写（不经值转换器——读向会把不可解行原样回读，写向 Encrypt 断言 32B 会误抛）。
/// </summary>
public static class DeviceSecretMigrator
{
    /// <returns>(加密/重加密行数, 跳过行数)</returns>
    public static (int Migrated, int Skipped) Migrate(IDbContextFactory<AppDbContext> plainFactory, DeviceSecretCipher cipher)
    {
        using var db = plainFactory.CreateDbContext();
        var migrated = 0;
        var skipped = 0;
        foreach (var d in db.Devices.ToList())
        {
            var raw = d.DeviceSecret;
            if (raw.Length == DeviceSecretCipher.PlainLen)
            {
                d.DeviceSecret = cipher.Encrypt(raw);
                migrated++;
            }
            else if (raw.Length == DeviceSecretCipher.CipherLen && raw[0] == cipher.CurrentKeyTag)
            {
                continue; // 已是当前钥密文（幂等）
            }
            else if (raw.Length == DeviceSecretCipher.CipherLen && cipher.PrevKeyTag == raw[0]
                     && cipher.TryDecryptWithPrev(raw, out var plain))
            {
                d.DeviceSecret = cipher.Encrypt(plain); // 轮换：prev 密文 → 当前钥重加密
                migrated++;
            }
            else
            {
                skipped++;
                Log.Error("静态加密迁移跳过不可解行（SEC-83、07 §14.3）：device={Id} device_secret 长度 {Len}B keyTag {Tag}（配错钥或密文损坏；恢复=解绑后重注册）",
                    d.Id, raw.Length, raw.Length > 0 ? raw[0].ToString("X2") : "-");
            }
        }
        if (migrated > 0)
            db.SaveChanges();
        return (migrated, skipped);
    }
}
