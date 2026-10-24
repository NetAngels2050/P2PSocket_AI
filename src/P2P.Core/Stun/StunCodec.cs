using System.Buffers.Binary;
using System.Net;
using P2P.Core.Crypto;

namespace P2P.Core.Stun;

/// <summary>
/// STUN-R：RFC 5389 Binding Request/Success 子集（02 §3）。
/// 头 20B：type(2) msgLen(2) magic(4)=0x2112A442 transactionId(12)；属性 TLV：type(2) len(2) value(4B 对齐补位)。
/// 全部整数字段网络序（大端）。
/// </summary>
public static class StunCodec
{
    public const ushort BindingRequest = 0x0001;
    public const ushort BindingSuccess = 0x0101;
    public const uint MagicCookie = 0x2112A442;
    public const int HeaderLen = 20;
    public const int TransactionIdLen = 12;

    public const ushort AttrXorMappedAddress = 0x0020;
    public const ushort AttrDeviceAuth = 0x8020;

    // 打洞交换属性（02 §5.2⑥，2026-10-24；comprehension-optional 区段 0x8000+——旧端忽略不炸）
    public const ushort AttrPunchSession = 0x8021;    // 请求属性：16B sessionId（TCP 连接即打洞交换事务）
    public const ushort AttrCandidates = 0x8022;      // 请求/响应属性：本机直连候选 [u8 计数][6B×n：addr4B+port2B 大端]
    public const ushort AttrPeerAddress = 0x8023;     // 响应属性：对端观测端点（明文地址 8B，与 RESPONSE-ORIGIN 同构）
    public const ushort AttrPeerCandidates = 0x8024;  // 响应属性：对端候选（同 CANDIDATES 编码）

    // RFC5780 NAT 行为发现属性（M3-15，05 §7.2；值按 RFC 5780 定值回填 02 §3）
    public const ushort AttrChangeRequest = 0x0003;   // 请求属性：4B flags（服务端从另一端点回包的载体）
    public const ushort AttrResponseOrigin = 0x802B;  // 响应属性：实际回包源（明文地址 8B）
    public const ushort AttrOtherAddress = 0x802C;    // 响应属性：另一端点（明文地址 8B，RFC3489 CHANGED-ADDRESS 同义）

    /// <summary>CHANGE-REQUEST flags：changeIP / changePort（任一置位 → 服务端从辅端点回包）。</summary>
    public const ushort ChangeIpFlag = 0x04;
    public const ushort ChangePortFlag = 0x02;

    public const int DeviceAuthValueLen = 16 + 16 + 8 + Mac.HashLen; // deviceId|nonce|ts|hmac = 72B
    private const int MacHashLen = Mac.HashLen;

    /// <summary>新事务 ID（12B 随机）。</summary>
    public static byte[] NewTransactionId() => RandomGenerator.Bytes(TransactionIdLen);

    // ── 组包 ─────────────────────────────────────────────────────────────

    /// <summary>组 Binding Request，携带 DEVICE-AUTH（02 §3.2：HMAC(deviceSecret, deviceId|nonce|ts|transactionId)）。
    /// changeFlags 非 null 时追加 CHANGE-REQUEST 属性（M3-15 RFC5780 filtering 测试；HMAC 输入不含属性区，认证不受影响）。
    /// punchSession 非 null 时追加 PUNCH-SESSION+CANDIDATES（02 §5.2⑥ 打洞交换事务：服务端收齐双端后
    /// 在两条连接上同刻回对端端点——连接保持打开、基准映射被钉活）。</summary>
    public static byte[] BuildBindingRequest(ReadOnlySpan<byte> transactionId, Guid deviceId,
        ReadOnlySpan<byte> deviceSecret, ulong tsMs, ReadOnlySpan<byte> nonce16, ushort? changeFlags = null,
        Guid? punchSession = null, IReadOnlyList<IPEndPoint>? candidates = null)
    {
        if (transactionId.Length != TransactionIdLen) throw new ArgumentException("事务 ID 须 12B");
        if (nonce16.Length != 16) throw new ArgumentException("nonce 须 16B");

        var auth = new byte[DeviceAuthValueLen];
        deviceId.ToByteArray().CopyTo(auth.AsSpan(0, 16));
        nonce16.CopyTo(auth.AsSpan(16, 16));
        BinaryPrimitives.WriteUInt64BigEndian(auth.AsSpan(32, 8), tsMs);

        // HMAC 输入 = deviceId|nonce|ts|transactionId（02 §3.2）
        var macInput = new byte[40 + TransactionIdLen];
        auth.AsSpan(0, 40).CopyTo(macInput.AsSpan(0, 40));
        transactionId.CopyTo(macInput.AsSpan(40));
        Mac.HmacSha256(deviceSecret, macInput).CopyTo(auth.AsSpan(40));

        var changeLen = changeFlags is null ? 0 : 4 + 4; // 属性头 4B + flags 4B（定长无补位）
        var sessionLen = punchSession is null ? 0 : 4 + Pad4(16)
            + (candidates is null || candidates.Count == 0 ? 0 : 4 + Pad4(CandidatesValueLen(candidates.Count)));
        var wire = new byte[HeaderLen + 4 + Pad4(DeviceAuthValueLen) + changeLen + sessionLen];
        WriteHeader(wire, BindingRequest, transactionId,
            attrLen: 4 + DeviceAuthValueLen + changeLen + sessionLen);
        WriteAttrHeader(wire.AsSpan(HeaderLen), AttrDeviceAuth, DeviceAuthValueLen);
        auth.CopyTo(wire.AsSpan(HeaderLen + 4));
        var offset = HeaderLen + 4 + Pad4(DeviceAuthValueLen);
        if (changeFlags is not null)
        {
            WriteAttrHeader(wire.AsSpan(offset), AttrChangeRequest, 4);
            BinaryPrimitives.WriteUInt32BigEndian(wire.AsSpan(offset + 4, 4), changeFlags.Value);
            offset += 8;
        }
        if (punchSession is not null)
        {
            WriteAttrHeader(wire.AsSpan(offset), AttrPunchSession, 16);
            punchSession.Value.ToByteArray().CopyTo(wire.AsSpan(offset + 4, 16));
            offset += 4 + Pad4(16);
            if (candidates is not null && candidates.Count > 0)
            {
                var value = EncodeCandidates(candidates);
                WriteAttrHeader(wire.AsSpan(offset), AttrCandidates, (ushort)value.Length);
                value.CopyTo(wire.AsSpan(offset + 4));
            }
        }
        return wire;
    }

    /// <summary>组 Binding Success Response：XOR-MAPPED-ADDRESS + 可选 RFC5780 属性（M3-15）——
    /// otherAddress=OTHER-ADDRESS（另一端点）、responseOrigin=RESPONSE-ORIGIN（本包实际回包源）；均缺省时输出与 M1 形状逐字节一致。
    /// peerAddress/peerCandidates（02 §5.2⑥ 打洞交换）：对端观测端点+对端候选——双端到齐时随各自应答同刻下发。</summary>
    public static byte[] BuildBindingResponse(ReadOnlySpan<byte> transactionId, IPAddress mapped, ushort port,
        IPEndPoint? otherAddress = null, IPEndPoint? responseOrigin = null,
        IPEndPoint? peerAddress = null, IReadOnlyList<IPEndPoint>? peerCandidates = null)
    {
        var value = EncodeXorMappedAddress(mapped, port);
        var other = otherAddress is null ? null : EncodePlainAddress(otherAddress.Address, (ushort)otherAddress.Port);
        var origin = responseOrigin is null ? null : EncodePlainAddress(responseOrigin.Address, (ushort)responseOrigin.Port);
        var peer = peerAddress is null ? null : EncodePlainAddress(peerAddress.Address, (ushort)peerAddress.Port);
        var peerCands = peerCandidates is null || peerCandidates.Count == 0
            ? null : EncodeCandidates(peerCandidates);
        var attrLen = 4 + value.Length
            + (other is null ? 0 : 4 + other.Length) + (origin is null ? 0 : 4 + origin.Length)
            + (peer is null ? 0 : 4 + peer.Length) + (peerCands is null ? 0 : 4 + peerCands.Length);
        var wire = new byte[HeaderLen + attrLen];
        WriteHeader(wire, BindingSuccess, transactionId, attrLen);
        var offset = HeaderLen;
        WriteAttrHeader(wire.AsSpan(offset), AttrXorMappedAddress, (ushort)value.Length);
        value.CopyTo(wire.AsSpan(offset + 4));
        offset += 4 + value.Length;
        if (other is not null)
        {
            WriteAttrHeader(wire.AsSpan(offset), AttrOtherAddress, (ushort)other.Length);
            other.CopyTo(wire.AsSpan(offset + 4));
            offset += 4 + other.Length;
        }
        if (origin is not null)
        {
            WriteAttrHeader(wire.AsSpan(offset), AttrResponseOrigin, (ushort)origin.Length);
            origin.CopyTo(wire.AsSpan(offset + 4));
            offset += 4 + origin.Length;
        }
        if (peer is not null)
        {
            WriteAttrHeader(wire.AsSpan(offset), AttrPeerAddress, (ushort)peer.Length);
            peer.CopyTo(wire.AsSpan(offset + 4));
            offset += 4 + peer.Length;
        }
        if (peerCands is not null)
        {
            WriteAttrHeader(wire.AsSpan(offset), AttrPeerCandidates, (ushort)peerCands.Length);
            peerCands.CopyTo(wire.AsSpan(offset + 4));
        }
        return wire;
    }

    // ── 解包 ─────────────────────────────────────────────────────────────

    public sealed record BindingResponse(byte[] TransactionId, IPEndPoint Mapped,
        IPEndPoint? OtherAddress = null, IPEndPoint? ResponseOrigin = null,
        IPEndPoint? PeerEndpoint = null, IPEndPoint[]? PeerCandidates = null);

    /// <summary>解析 Success Response（客户端侧）：校验 magic/type，取首个 XOR-MAPPED-ADDRESS 与可选 RFC5780 属性
    /// （OTHER-ADDRESS/RESPONSE-ORIGIN——缺失/畸形属性容忍为 null，不影响主字段）。
    /// PEER-ADDRESS/PEER-CANDIDATES（02 §5.2⑥ 打洞交换）：对端观测端点+候选——交换事务的核心载荷，
    /// 缺失视为非交换应答（普通探测）。</summary>
    public static bool TryParseBindingResponse(ReadOnlySpan<byte> wire, out BindingResponse? response)
    {
        response = null;
        if (wire.Length < HeaderLen || !HeaderOk(wire, BindingSuccess))
            return false;

        var transactionId = wire.Slice(8, TransactionIdLen).ToArray();
        if (!TryGetAttribute(wire, AttrXorMappedAddress, out var value) || value.Length != 8 || value[1] != 0x01)
            return false; // 仅 IPv4（02 §3 M1 范围）
        var xPort = BinaryPrimitives.ReadUInt16BigEndian(value.Slice(2, 2));
        var port = (ushort)(xPort ^ (MagicCookie >> 16));
        var addr = new byte[4]; // 逐字节与 cookie 异或后按网络序构造（IPAddress(uint) 是小端语义，不可用）
        for (var i = 0; i < 4; i++)
            addr[i] = (byte)(value[4 + i] ^ ((MagicCookie >> (24 - 8 * i)) & 0xFF));
        IPEndPoint? other = null, origin = null, peer = null;
        if (TryGetAttribute(wire, AttrOtherAddress, out var oa) && TryDecodePlainAddress(oa, out var oep))
            other = oep;
        if (TryGetAttribute(wire, AttrResponseOrigin, out var ro) && TryDecodePlainAddress(ro, out var rep))
            origin = rep;
        if (TryGetAttribute(wire, AttrPeerAddress, out var pa) && TryDecodePlainAddress(pa, out var pep))
            peer = pep;
        IPEndPoint[]? peerCands = null;
        if (TryGetAttribute(wire, AttrPeerCandidates, out var pc) && TryDecodeCandidates(pc, out var cands))
            peerCands = cands;
        response = new BindingResponse(transactionId, new IPEndPoint(new IPAddress(addr), port), other, origin,
            peer, peerCands);
        return true;
    }

    // ── 打洞交换属性（02 §5.2⑥）──────────────────────────────────────

    /// <summary>候选编码：[u8 计数][6B×n：addr 4B 大端 + port 2B 大端]（≤8 个，IPv4）。</summary>
    public const int MaxCandidates = 8;

    private static int CandidatesValueLen(int count) => 1 + 6 * count;

    private static byte[] EncodeCandidates(IReadOnlyList<IPEndPoint> candidates)
    {
        var count = Math.Min(candidates.Count, MaxCandidates);
        var value = new byte[CandidatesValueLen(count)];
        value[0] = (byte)count;
        for (var i = 0; i < count; i++)
        {
            var addr = candidates[i].Address;
            if (addr.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) continue;
            addr.GetAddressBytes().CopyTo(value.AsSpan(1 + 6 * i, 4));
            BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(1 + 6 * i + 4, 2), (ushort)candidates[i].Port);
        }
        return value;
    }

    private static bool TryDecodeCandidates(ReadOnlySpan<byte> value, out IPEndPoint[]? candidates)
    {
        candidates = null;
        if (value.Length < 1) return false;
        var count = value[0];
        if (count > MaxCandidates || value.Length < CandidatesValueLen(count)) return false;
        var list = new IPEndPoint[count];
        for (var i = 0; i < count; i++)
        {
            var port = BinaryPrimitives.ReadUInt16BigEndian(value.Slice(1 + 6 * i + 4, 2));
            list[i] = new IPEndPoint(new IPAddress(value.Slice(1 + 6 * i, 4).ToArray()), port);
        }
        candidates = list;
        return true;
    }

    /// <summary>提取 PUNCH-SESSION（服务端侧）：无属性/长度非 16B = 普通探测事务（false）。</summary>
    public static bool TryGetPunchSession(ReadOnlySpan<byte> wire, out Guid sessionId)
    {
        sessionId = Guid.Empty;
        if (!TryGetAttribute(wire, AttrPunchSession, out var value) || value.Length != 16) return false;
        sessionId = new Guid(value.ToArray());
        return true;
    }

    /// <summary>提取 CANDIDATES（服务端侧）：缺失/畸形 = 空表。</summary>
    public static IPEndPoint[] ParseCandidates(ReadOnlySpan<byte> wire)
        => TryGetAttribute(wire, AttrCandidates, out var value) && TryDecodeCandidates(value, out var cands)
            ? cands ?? [] : [];

    /// <summary>提取 CHANGE-REQUEST flags（服务端侧，M3-15）：缺属性/畸形=0（按普通 Binding 处理）。
    /// 任一 flag 置位即要求从另一端点回包（RFC5780；单"另一端点"实现不区分 IP/Port 方向）。</summary>
    public static ushort ParseChangeRequest(ReadOnlySpan<byte> wire)
    {
        return TryGetAttribute(wire, AttrChangeRequest, out var value) && value.Length == 4
            ? (ushort)BinaryPrimitives.ReadUInt32BigEndian(value)
            : (ushort)0;
    }

    public sealed record DeviceAuth(Guid DeviceId, byte[] Nonce, ulong TsMs, byte[] Hmac, byte[] TransactionId);

    /// <summary>提取并校验 DEVICE-AUTH（服务端侧）；结构/HMAC 任一不符返回 false（静默丢弃，02 §3.2）。</summary>
    public static bool TryParseDeviceAuth(ReadOnlySpan<byte> wire, Func<Guid, byte[]?> secretByDevice)
    {
        if (wire.Length < HeaderLen || !HeaderOk(wire, BindingRequest))
            return false;
        var transactionId = wire.Slice(8, TransactionIdLen);

        if (!TryGetAttribute(wire, AttrDeviceAuth, out var value) || value.Length != DeviceAuthValueLen)
            return false;
        var deviceId = new Guid(value.Slice(0, 16).ToArray());
        var secret = secretByDevice(deviceId);
        if (secret is null) return false; // 未注册设备：静默丢弃

        var expected = Mac.HmacSha256(secret, BuildAuthMacInput(value, transactionId));
        return Mac.Verify(value.Slice(40, MacHashLen), expected);
    }

    /// <summary>DEVICE-AUTH 字段拆解（服务端校验 ts 窗口/nonce 去重用）。</summary>
    public static DeviceAuth? ParseDeviceAuthFields(ReadOnlySpan<byte> wire)
    {
        if (wire.Length < HeaderLen || !HeaderOk(wire, BindingRequest))
            return null;
        var transactionId = wire.Slice(8, TransactionIdLen);
        if (!TryGetAttribute(wire, AttrDeviceAuth, out var value) || value.Length != DeviceAuthValueLen)
            return null;
        return new DeviceAuth(
            new Guid(value.Slice(0, 16).ToArray()),
            value.Slice(16, 16).ToArray(),
            BinaryPrimitives.ReadUInt64BigEndian(value.Slice(32, 8)),
            value.Slice(40, MacHashLen).ToArray(),
            transactionId.ToArray());
    }

    // ── 内部 ─────────────────────────────────────────────────────────────

    /// <summary>XOR-MAPPED-ADDRESS 编码：family(1)=0x01 + port^(cookie>>16) + addr^cookie（RFC 5389 §15.2）。</summary>
    private static byte[] EncodeXorMappedAddress(IPAddress mapped, ushort port)
    {
        var addrBytes = mapped.GetAddressBytes();
        if (addrBytes.Length != 4) throw new ArgumentException("M1 仅支持 IPv4");
        var value = new byte[8];
        value[1] = 0x01;
        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(2, 2), (ushort)(port ^ (MagicCookie >> 16)));
        for (var i = 0; i < 4; i++)
            value[4 + i] = (byte)(addrBytes[i] ^ ((MagicCookie >> (24 - 8 * i)) & 0xFF));
        return value;
    }

    /// <summary>明文地址编码（RFC5780 RESPONSE-ORIGIN/OTHER-ADDRESS，MAPPED-ADDRESS 同构）：[0]=0 保留 + [1]=family 0x01 + port 2B 大端 + addr 4B。</summary>
    private static byte[] EncodePlainAddress(IPAddress address, ushort port)
    {
        var addrBytes = address.GetAddressBytes();
        if (addrBytes.Length != 4) throw new ArgumentException("M1 仅支持 IPv4");
        var value = new byte[8];
        value[1] = 0x01;
        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(2, 2), port);
        addrBytes.CopyTo(value.AsSpan(4, 4));
        return value;
    }

    /// <summary>明文地址解码（仅 IPv4；畸形返回 false 且 out null——容忍解析）。</summary>
    private static bool TryDecodePlainAddress(ReadOnlySpan<byte> value, out IPEndPoint? endpoint)
    {
        endpoint = null;
        if (value.Length != 8 || value[0] != 0 || value[1] != 0x01)
            return false;
        var port = BinaryPrimitives.ReadUInt16BigEndian(value.Slice(2, 2));
        endpoint = new IPEndPoint(new IPAddress(value.Slice(4, 4).ToArray()), port);
        return true;
    }

    private static byte[] BuildAuthMacInput(ReadOnlySpan<byte> authValue72, ReadOnlySpan<byte> transactionId)
    {
        var input = new byte[40 + TransactionIdLen];
        authValue72.Slice(0, 40).CopyTo(input.AsSpan(0, 40)); // deviceId|nonce|ts
        transactionId.CopyTo(input.AsSpan(40));
        return input;
    }

    private static bool HeaderOk(ReadOnlySpan<byte> wire, ushort expectedType)
    {
        var type = BinaryPrimitives.ReadUInt16BigEndian(wire.Slice(0, 2));
        var msgLen = BinaryPrimitives.ReadUInt16BigEndian(wire.Slice(2, 2));
        var cookie = BinaryPrimitives.ReadUInt32BigEndian(wire.Slice(4, 4));
        return type == expectedType && cookie == MagicCookie
            && wire.Length == HeaderLen + msgLen; // UDP 报文长度即消息长度
    }

    private static void WriteHeader(Span<byte> dst, ushort type, ReadOnlySpan<byte> transactionId, int attrLen)
    {
        BinaryPrimitives.WriteUInt16BigEndian(dst.Slice(0, 2), type);
        BinaryPrimitives.WriteUInt16BigEndian(dst.Slice(2, 2), (ushort)attrLen);
        BinaryPrimitives.WriteUInt32BigEndian(dst.Slice(4, 4), MagicCookie);
        transactionId.CopyTo(dst.Slice(8, TransactionIdLen));
    }

    private static void WriteAttrHeader(Span<byte> dst, ushort type, ushort len)
    {
        BinaryPrimitives.WriteUInt16BigEndian(dst.Slice(0, 2), type);
        BinaryPrimitives.WriteUInt16BigEndian(dst.Slice(2, 2), len);
    }

    /// <summary>取首个匹配属性；属性区越界/截断视为不存在（容忍解析）。</summary>
    private static bool TryGetAttribute(ReadOnlySpan<byte> wire, ushort attrType, out ReadOnlySpan<byte> value)
    {
        value = default;
        var offset = HeaderLen;
        while (offset + 4 <= wire.Length)
        {
            var type = BinaryPrimitives.ReadUInt16BigEndian(wire.Slice(offset, 2));
            var len = BinaryPrimitives.ReadUInt16BigEndian(wire.Slice(offset + 2, 2));
            var valueStart = offset + 4;
            if (valueStart + len > wire.Length)
                return false; // 长度越界：截断容错
            if (type == attrType)
            {
                value = wire.Slice(valueStart, len);
                return true;
            }
            offset = valueStart + Pad4(len);
        }
        return false;
    }

    private static int Pad4(int len) => (len + 3) & ~3;
}
