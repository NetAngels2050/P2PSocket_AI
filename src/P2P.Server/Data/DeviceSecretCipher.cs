using System.Security.Cryptography;
using Serilog;

namespace P2P.Server.Data;

/// <summary>
/// 静态数据加密（SEC-83、07 §14.3）：devices.device_secret 列级 AES-256-GCM。
/// 存储格式 [keyTag 1B][nonce 12B][ct 32B‖tag 16B]（32B 明文 → 61B 密文）；
/// keyTag = SHA-256(masterKey)[0] 自动派生（免额外配置项）；轮换双钥 = 当前钥加密/解密 +
/// prev 钥（可选）仅参与解密（keyTag≠当前 tag 的密文以 prev 试解）。
/// 解密失败不冒泡（OQ-22② 定案）：返回原值——该行凭据等价丢钥口径失效（校验自然失败），
/// ERROR 日志+进程内计数（安全中心 Encryption.DecryptFailures 可见；重启清零）。
/// </summary>
public sealed class DeviceSecretCipher
{
    public const int PlainLen = 32;   // 32B HMAC 密钥（Entities.Users DeviceSecret）
    public const int CipherLen = 61;  // 1 keyTag + 12 nonce + 32 ct + 16 tag
    private const int NonceLen = 12;
    private const int TagLen = 16;
    private const int KeyHexLen = 64; // 32B → 64 hex

    private readonly byte[] _currentKey;
    private readonly byte[]? _prevKey;

    public byte CurrentKeyTag { get; }
    public byte? PrevKeyTag { get; }

    /// <summary>进程内解密失败计数（运行时读向累计；迁移器跳过行不在此计数）。</summary>
    public int DecryptFailures { get; private set; }

    public DeviceSecretCipher(string masterKeyHex, string? masterKeyPrevHex = null)
    {
        _currentKey = ParseKey(masterKeyHex);
        CurrentKeyTag = KeyTag(_currentKey);
        if (!string.IsNullOrEmpty(masterKeyPrevHex))
        {
            try
            {
                _prevKey = ParseKey(masterKeyPrevHex);
                PrevKeyTag = KeyTag(_prevKey);
            }
            catch (ArgumentException)
            {
                // 非法 prev 不阻断加密启用——仅当前钥生效（轮换过渡期配错 prev 的降级语义）
                Log.Error("静态数据加密：masterKeyPrev 非法（须 64 位 hex/32B），忽略 prev 仅当前钥生效（SEC-83、07 §14.3）");
            }
        }
    }

    /// <summary>装配缝（Program）：缺失/非法返回 null+原因——缺失不阻断启动口径（07 §14.3：P2 纵深防御层，阻断会使存量部署升级即断服）。</summary>
    public static DeviceSecretCipher? TryCreate(string? masterKey, string? masterKeyPrev, out string reason)
    {
        if (string.IsNullOrWhiteSpace(masterKey))
        {
            reason = "未配置 security.masterKey（64 位 hex=32B；环境变量 P2P_MASTER_KEY 优先）";
            return null;
        }
        try
        {
            reason = "";
            return new DeviceSecretCipher(masterKey, masterKeyPrev);
        }
        catch (ArgumentException ex)
        {
            reason = $"masterKey 非法（{ex.Message}）——按未配置处理不阻断启动";
            return null;
        }
    }

    /// <summary>写向（EF 值转换器）：恒 61B 密文——随机 nonce 使同明文两次加密不同值（防库内等值比对）；非 32B 明文抛出（防不可解原值二次加密的隐性损坏）。</summary>
    public byte[] Encrypt(byte[] plain)
    {
        if (plain.Length != PlainLen)
            throw new ArgumentException($"device_secret 明文须 {PlainLen}B（实得 {plain.Length}B）");
        var stored = new byte[CipherLen];
        stored[0] = CurrentKeyTag;
        var nonce = RandomNumberGenerator.GetBytes(NonceLen);
        nonce.CopyTo(stored, 1);
        using var aes = new AesGcm(_currentKey, TagLen);
        aes.Encrypt(nonce, plain, stored.AsSpan(1 + NonceLen, PlainLen),
            stored.AsSpan(1 + NonceLen + PlainLen, TagLen));
        return stored;
    }

    /// <summary>读向（EF 值转换器）：失败/异形返回原值——凭据校验自然失败=失效口径（OQ-22②），ERROR+计数。</summary>
    public byte[] DecryptOrRaw(byte[] stored)
    {
        if (stored.Length == CipherLen)
        {
            if (stored[0] == CurrentKeyTag && TryDecrypt(stored, _currentKey, out var plain))
                return plain;
            if (_prevKey is not null && PrevKeyTag == stored[0] && TryDecrypt(stored, _prevKey, out var plainPrev))
                return plainPrev;
        }
        DecryptFailures++;
        Log.Error("device_secret 解密失败（SEC-83/OQ-22②）：长度 {Len}B keyTag {Tag}——该行凭据视为失效（配错钥或密文损坏；恢复=解绑后重注册）",
            stored.Length, stored.Length > 0 ? stored[0].ToString("X2") : "-");
        return stored;
    }

    /// <summary>prev 钥试解（迁移器轮换专用；失败不计数——运行时读向计数属 DecryptOrRaw）。</summary>
    public bool TryDecryptWithPrev(byte[] stored, out byte[] plain)
    {
        plain = [];
        return _prevKey is not null && TryDecrypt(stored, _prevKey, out plain);
    }

    private static bool TryDecrypt(byte[] stored, byte[] key, out byte[] plain)
    {
        plain = new byte[PlainLen];
        try
        {
            using var aes = new AesGcm(key, TagLen);
            aes.Decrypt(stored.AsSpan(1, NonceLen),
                stored.AsSpan(1 + NonceLen, PlainLen),
                stored.AsSpan(1 + NonceLen + PlainLen, TagLen),
                plain);
            return true;
        }
        catch (CryptographicException)
        {
            return false; // GCM 校验失败（密文损坏/钥不匹配）
        }
    }

    /// <summary>64 hex（大小写均可）→ 32B；trim 后非 64 位或非 hex 抛 ArgumentException。</summary>
    public static byte[] ParseKey(string hex)
    {
        var t = hex.Trim();
        if (t.Length != KeyHexLen)
            throw new ArgumentException($"须为 {KeyHexLen} 位 hex（32B），实得 {t.Length} 位");
        try
        {
            return Convert.FromHexString(t);
        }
        catch (FormatException)
        {
            throw new ArgumentException($"须为 {KeyHexLen} 位 hex（32B）");
        }
    }

    /// <summary>keyTag = SHA-256(key)[0]（07 §14.3 自动派生）。</summary>
    public static byte KeyTag(byte[] key) => SHA256.HashData(key)[0];
}
