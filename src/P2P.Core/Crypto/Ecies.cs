using System.Security.Cryptography;

namespace P2P.Core.Crypto;

/// <summary>
/// ECIES 封装（OQ-15：RegisterAck.deviceSecret 以客户端 staticPubKey 加密下发）。
/// 线格式：[ephPub 65B][nonce 12B][AES-256-GCM 密文+tag]；密钥 = HKDF(ECDH(ephS, recipientStatic), info)。
/// info 参数化（M5-06/SEC-26）：登录族用 "pcp-login-v1" 域分离（防与注册族密文互解，07 §10.1），
/// 缺省 "p2p-ecies" 不变——既有 RegisterAck 调用零改动。
/// </summary>
public static class Ecies
{
    private const int EphPubLen = 65;

    public static byte[] Encrypt(ReadOnlySpan<byte> recipientPub65, ReadOnlySpan<byte> plaintext)
        => Encrypt(recipientPub65, plaintext, "p2p-ecies"u8);

    public static byte[] Encrypt(ReadOnlySpan<byte> recipientPub65, ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> info)
    {
        using var eph = EcKeyPair.Generate();
        var shared = eph.DeriveSharedKey(recipientPub65);
        var key = Hkdf.Derive(shared, [], info, 32);
        var nonce = RandomGenerator.Bytes(Aead.NonceLen);
        var ct = Aead.Seal(key, nonce, [], plaintext);
        CryptoUtil.Zero(shared);
        CryptoUtil.Zero(key);

        var boxed = new byte[EphPubLen + Aead.NonceLen + ct.Length];
        eph.ExportPublicKey().AsSpan().CopyTo(boxed.AsSpan(0, EphPubLen));
        nonce.AsSpan().CopyTo(boxed.AsSpan(EphPubLen, Aead.NonceLen));
        ct.AsSpan().CopyTo(boxed.AsSpan(EphPubLen + Aead.NonceLen));
        return boxed;
    }

    /// <summary>以本端私钥开箱；篡改/错钥抛 <see cref="CryptographicException"/>。</summary>
    public static byte[] Decrypt(EcKeyPair recipientKey, ReadOnlySpan<byte> boxed)
        => Decrypt(recipientKey, boxed, "p2p-ecies"u8);

    /// <summary>以本端私钥开箱（指定 info 域——登录族 "pcp-login-v1"）；篡改/错钥抛 <see cref="CryptographicException"/>。</summary>
    public static byte[] Decrypt(EcKeyPair recipientKey, ReadOnlySpan<byte> boxed, ReadOnlySpan<byte> info)
    {
        if (boxed.Length < EphPubLen + Aead.NonceLen + Aead.TagLen)
            throw new CryptographicException("ECIES 密文长度不足");
        var shared = recipientKey.DeriveSharedKey(boxed[..EphPubLen]);
        var key = Hkdf.Derive(shared, [], info, 32);
        try
        {
            return Aead.Open(key, boxed.Slice(EphPubLen, Aead.NonceLen), [],
                boxed[(EphPubLen + Aead.NonceLen)..]);
        }
        finally
        {
            CryptoUtil.Zero(shared);
            CryptoUtil.Zero(key);
        }
    }
}
