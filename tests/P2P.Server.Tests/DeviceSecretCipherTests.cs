using P2P.Core.Crypto;
using P2P.Server.Data;
using Xunit;

namespace P2P.Server.Tests;

/// <summary>
/// M5-13 静态数据加密核心单测（SEC-83、07 §14.3）：存储格式 [keyTag 1B][nonce 12B]
/// [AES-256-GCM ct‖tag]（32B→61B）；随机 nonce 防等值比对；prev 双钥轮换语义；
/// 解密失败不冒泡（返回原值=凭据失效口径，OQ-22②）+计数；TryCreate 缺失/非法装配缝。
/// </summary>
public sealed class DeviceSecretCipherTests
{
    private static string Hex() => Convert.ToHexString(RandomGenerator.Bytes(32)).ToLowerInvariant();

    private static DeviceSecretCipher NewCipher(string? prev = null) => new(Hex(), prev);

    [Fact]
    public void 加密_61B密文_keyTag一致_解密回明文()
    {
        var cipher = NewCipher();
        var plain = RandomGenerator.Bytes(32);

        var stored = cipher.Encrypt(plain);

        Assert.Equal(61, stored.Length);
        Assert.Equal(cipher.CurrentKeyTag, stored[0]);
        Assert.Equal(plain, cipher.DecryptOrRaw(stored));
    }

    [Fact]
    public void 同明文两次加密_密文不同_均可解回()
    {
        var cipher = NewCipher();
        var plain = RandomGenerator.Bytes(32);

        var a = cipher.Encrypt(plain);
        var b = cipher.Encrypt(plain);

        Assert.NotEqual(a, b); // 随机 nonce——防库内等值比对
        Assert.Equal(plain, cipher.DecryptOrRaw(a));
        Assert.Equal(plain, cipher.DecryptOrRaw(b));
    }

    [Fact]
    public void 解密失败_返回原值_计数递增()
    {
        var cipher = NewCipher();
        var unknownTag = new byte[61];      // keyTag 0——非当前/prev 钥（配错钥形态）
        var tampered = cipher.Encrypt(RandomGenerator.Bytes(32));
        tampered[40] ^= 0xFF;               // 篡改 ct 段——GCM 校验失败
        var legacyPlain = RandomGenerator.Bytes(32); // 32B 明文行（迁移遗漏/库被替换形态）

        Assert.Equal(0, cipher.DecryptFailures);
        Assert.Same(unknownTag, cipher.DecryptOrRaw(unknownTag));
        Assert.Same(tampered, cipher.DecryptOrRaw(tampered));
        Assert.Same(legacyPlain, cipher.DecryptOrRaw(legacyPlain));
        Assert.Equal(3, cipher.DecryptFailures);
    }

    [Fact]
    public void prev钥密文_当前钥实例可解_轮换双钥语义()
    {
        var prevHex = Hex();
        var prev = new DeviceSecretCipher(prevHex);
        var plain = RandomGenerator.Bytes(32);
        var stored = prev.Encrypt(plain);

        var rotated = new DeviceSecretCipher(Hex(), prevHex); // 当前钥换新+prev 过渡

        Assert.NotEqual(prev.CurrentKeyTag, rotated.CurrentKeyTag);
        Assert.Equal(plain, rotated.DecryptOrRaw(stored)); // keyTag=prev → prev 试解成功
        Assert.Equal(0, rotated.DecryptFailures);
    }

    [Fact]
    public void TryCreate_缺失与非法返回null_合法创建()
    {
        Assert.Null(DeviceSecretCipher.TryCreate(null, null, out var r1));
        Assert.Contains("未配置", r1);
        Assert.Null(DeviceSecretCipher.TryCreate("  ", null, out _));
        Assert.Null(DeviceSecretCipher.TryCreate("abcd", null, out var r2)); // 非 64 位
        Assert.Contains("按未配置处理", r2);
        Assert.Null(DeviceSecretCipher.TryCreate(new string('x', 64), null, out var r3)); // 非 hex
        Assert.Contains("按未配置处理", r3);

        var key = Hex();
        var cipher = DeviceSecretCipher.TryCreate(key, key, out var r4);
        Assert.NotNull(cipher);
        Assert.Equal("", r4);
        Assert.NotNull(cipher.PrevKeyTag); // prev=当前钥同钥：双 tag 相等（无害——迁移首分支命中）
    }

    [Fact]
    public void 非法prev_忽略不阻断_仅当前钥生效()
    {
        var cipher = new DeviceSecretCipher(Hex(), "zz-not-hex"); // prev 非法：ctor 内吞+忽略

        Assert.Null(cipher.PrevKeyTag);
        var plain = RandomGenerator.Bytes(32);
        Assert.Equal(plain, cipher.DecryptOrRaw(cipher.Encrypt(plain))); // 当前钥全链正常
    }

    [Fact]
    public void ParseKey_大小写与空白兼容()
    {
        var key = RandomGenerator.Bytes(32);
        var hex = Convert.ToHexString(key); // 大写+无空白

        Assert.Equal(key, DeviceSecretCipher.ParseKey($"  {hex.ToLowerInvariant()}  "));
    }
}
