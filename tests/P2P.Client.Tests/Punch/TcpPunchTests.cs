using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using P2P.Client.Punch;
using P2P.Client.Tunnel;
using P2P.Core.Crypto;
using P2P.Core.Protocol;
using P2P.Core.Tunnel;
using Xunit;

namespace P2P.Client.Tests;

// ── M2-16 单测（任务清单完成判定：N 条并发目标端口偏移正确、第 1 条沿用 L、胜出取消其余 N−1、
//    N_A≠N_B 必 miss（对称性验证）、N 取 0x70 Ack 回填值；TCP 承载 u16 前缀分帧）──

/// <summary>端口预测纯逻辑（02 §5.2：目标统一 portTcp+(N−1)，单元素偏移扩展点）。</summary>
public sealed class TcpPunchPlanTests
{
    [Theory]
    [InlineData(1, 0)] // 直连 STUN 端口
    [InlineData(2, 1)]
    [InlineData(3, 2)] // 默认
    [InlineData(4, 3)]
    [InlineData(5, 4)] // 上限
    public void 偏移表_单元素N减一(int n, int offset)
    {
        Assert.Equal([offset], TcpPunchPlan.Offsets(n));
        Assert.Equal(40000 + offset, TcpPunchPlan.TargetPort(40000, n));
    }

    [Theory]
    [InlineData(1, 2)]
    [InlineData(2, 4)]
    [InlineData(3, 5)]
    [InlineData(1, 5)]
    public void 不对称N_目标端口必错位_代数上必miss(int nA, int nB)
    {
        // 对称性硬约束（02 §5.2②）：双方 N 不一致 → A 瞄准的端口 ≠ B 实际落位端口 → 预测基准错位
        Assert.NotEqual(TcpPunchPlan.TargetPort(50000, nA), TcpPunchPlan.TargetPort(50000, nB));
    }
}

/// <summary>TCP 承载分帧（02 §6.2 u16 长度前缀）：往返/有序、关闭/截断/非法前缀、发送侧越界。</summary>
public sealed class TcpFrameTransportTests
{
    private static (Socket A, Socket B) ConnectedPair()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start(2);
        var a = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        a.Connect(listener.LocalEndpoint!);
        var b = listener.AcceptSocket();
        listener.Stop();
        return (a, b);
    }

    [Fact]
    public async Task 帧往返_多帧有序()
    {
        var (sa, sb) = ConnectedPair();
        await using var ta = new TcpFrameTransport(sa);
        await using var tb = new TcpFrameTransport(sb);
        var frames = new[]
        {
            PtpFrameCodec.BuildHandshake(PtpFrameType.THello1, new byte[50]),
            PtpFrameCodec.BuildHandshake(PtpFrameType.THello2, new byte[120]),
            PtpFrameCodec.BuildHandshake(PtpFrameType.TConfirm, new byte[32]),
        };
        foreach (var f in frames) await ta.SendAsync(f);
        foreach (var expected in frames)
            Assert.Equal(expected, await tb.ReceiveAsync());
        Assert.NotNull(ta.RemoteEndPoint); // 端点快照（打洞结果上报用）
        Assert.Equal(((IPEndPoint)sa.RemoteEndPoint!).Port, ta.RemoteEndPoint!.Port);
    }

    [Fact]
    public async Task 对端关闭_返回null()
    {
        var (sa, sb) = ConnectedPair();
        await using var ta = new TcpFrameTransport(sa);
        sb.Dispose();
        Assert.Null(await ta.ReceiveAsync());
    }

    [Fact]
    public async Task 中途截断_返回null()
    {
        var (sa, sb) = ConnectedPair();
        await using var ta = new TcpFrameTransport(sa);
        var prefix = new byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(prefix, 100);
        await sb.SendAsync(prefix, SocketFlags.None);
        await sb.SendAsync(new byte[40], SocketFlags.None); // 声明 100 只到 40
        sb.Dispose();
        Assert.Null(await ta.ReceiveAsync());
    }

    [Fact]
    public async Task 非法前缀_过短与超限_返回null()
    {
        var (sa, sb) = ConnectedPair();
        await using var ta = new TcpFrameTransport(sa);
        var prefix = new byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(prefix, PtpHeader.WireLen - 1); // 过短（< 帧头 16B）
        await sb.SendAsync(prefix, SocketFlags.None);
        Assert.Null(await ta.ReceiveAsync());
        BinaryPrimitives.WriteUInt16LittleEndian(prefix, TcpFrameTransport.MaxFrame + 1); // 超帧上限
        await sb.SendAsync(prefix, SocketFlags.None);
        Assert.Null(await ta.ReceiveAsync());
    }

    [Fact]
    public async Task 发送侧越界与过短_拒绝()
    {
        var (sa, _) = ConnectedPair();
        await using var ta = new TcpFrameTransport(sa);
        await Assert.ThrowsAsync<ProtocolException>(() =>
            ta.SendAsync(new byte[TcpFrameTransport.MaxFrame + 1]).AsTask());
        await Assert.ThrowsAsync<ProtocolException>(() => ta.SendAsync(new byte[10]).AsTask());
    }
}

/// <summary>TcpPunchFleet：listen(L)+N 并发 connect、第 1 条沿用 L、入池等待首帧、胜出释放其余关闭。</summary>
public sealed class TcpPunchFleetTests
{
    /// <summary>测试专有端口带内取 port..port+span-1 连续空闲段（24000-28000，避开 Windows
    /// 临时端口段 49152+）。曾用 :0 探测——临时端口顺序分配下，并行测试类的 :0 监听常与本类
    /// 探测结果相邻取号，"死端口"假设被打洞 connect 击中对方 echo 服务（FailedConnects 永不到
    /// 位 + 对方 Connections 计数被污染，本地冷启与 CI 同型翻车实录）。带内 :0 分配器不踏足，
    /// 仅剩带内随机对撞（~1/7000，探测重试兜底）。</summary>
    private static int FreePort(int span = 1)
    {
        while (true)
        {
            var basePort = Random.Shared.Next(24000, 28000 - span);
            List<TcpListener>? taken = null;
            try
            {
                for (var p = basePort; p < basePort + span; p++)
                {
                    var l = new TcpListener(IPAddress.Loopback, p);
                    l.Start();
                    (taken ??= []).Add(l);
                }
                return basePort;
            }
            catch (SocketException) { /* 带内对撞：换段重探 */ }
            finally
            {
                if (taken is not null)
                    foreach (var l in taken) l.Stop();
            }
        }
    }

    /// <summary>取一个与 keepClear 各端口（含 ±1 邻位）均不同的空闲端口——端口预测类测试的
    /// connect 目标/监听位须与已知端口保持邻位距离（带内随机对撞由探测重试兜底）。</summary>
    private static int FreePortApart(params int[] keepClear)
    {
        while (true)
        {
            var p = FreePort();
            if (!keepClear.Any(k => Math.Abs(k - p) <= 1)) return p;
        }
    }

    private static byte[] Hello1Wire(int payload = 50) =>
        PtpFrameCodec.BuildHandshake(PtpFrameType.THello1, new byte[payload]);

    private static async Task WriteFramedAsync(Socket s, byte[] frame)
    {
        var wire = new byte[2 + frame.Length];
        BinaryPrimitives.WriteUInt16LittleEndian(wire, (ushort)frame.Length);
        frame.CopyTo(wire, 2);
        await s.SendAsync(wire, SocketFlags.None);
    }

    private static async Task<List<Socket>> AcceptAsync(TcpListener listener, int count, string what)
    {
        var accepted = new List<Socket>();
        var deadline = Environment.TickCount64 + 5000;
        while (accepted.Count < count)
        {
            if (Environment.TickCount64 > deadline) throw new TimeoutException($"等待超时：{what}");
            while (listener.Pending() && accepted.Count < count)
                accepted.Add(listener.AcceptSocket());
            await Task.Delay(10);
        }
        return accepted;
    }

    private static async Task UntilAsync(Func<bool> condition, string what)
    {
        var deadline = Environment.TickCount64 + 5000;
        while (!condition())
        {
            if (Environment.TickCount64 > deadline) throw new TimeoutException($"等待超时：{what}");
            await Task.Delay(10);
        }
    }

    /// <summary>轮询等待对端观察到 EOF（连接被关）。</summary>
    private static async Task AssertEofAsync(Socket s)
    {
        var deadline = Environment.TickCount64 + 5000;
        while (Environment.TickCount64 < deadline)
        {
            if (s.Poll(0, SelectMode.SelectRead) && s.Available == 0) return;
            await Task.Delay(10);
        }
        throw new Xunit.Sdk.XunitException("未见 EOF：连接未关闭");
    }

    [Fact]
    public async Task 并发connect_第1条沿用端口L_全部打向统一目标端口()
    {
        var l = FreePort();
        var targetPort = FreePortApart(l);
        var listener = new TcpListener(IPAddress.Loopback, targetPort);
        listener.Start(8);

        await using var fleet = TcpPunchFleet.Create(IPAddress.Loopback, l,
            new IPEndPoint(IPAddress.Loopback, targetPort), concurrency: 3, PtpFrameType.THello1);
        var accepted = await AcceptAsync(listener, 3, "对端接受 3 条 connect");

        Assert.Equal(l, fleet.FirstConnectLocalPort);            // 第 1 条沿用 L（02 §5.2③b）
        Assert.Contains(accepted, s => ((IPEndPoint)s.RemoteEndPoint!).Port == l); // 对端看到源端口 L
        Assert.Equal(0, fleet.FailedConnects);
        await UntilAsync(() => fleet.LiveConnections == 3, "三条连接全部入池"); // 入池异步于对端 accept
        foreach (var s in accepted) s.Dispose();
    }

    [Fact]
    public async Task listen收连接入池_等待首帧命中()
    {
        var l = FreePort();
        var closed = FreePortApart(l); // connect 目标无人监听：全部拒连，仅剩 listen 路径
        await using var fleet = TcpPunchFleet.Create(IPAddress.Loopback, l,
            new IPEndPoint(IPAddress.Loopback, closed), concurrency: 2, PtpFrameType.THello1);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, l); // 外部连入端口 L → listen accept 入池
        var wire = Hello1Wire();
        await WriteFramedAsync(client.Client, wire);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var (transport, frame) = await fleet.WaitFrameAsync(cts.Token);
        Assert.Equal(wire, frame); // 首帧命中 awaitedType
        Assert.Equal(((IPEndPoint)client.Client.LocalEndPoint!).Port, transport.RemoteEndPoint!.Port);
        Assert.Single(fleet.Connections);
    }

    [Fact]
    public async Task 胜出释放_其余连接关闭_胜者可用()
    {
        var l = FreePort();
        var targetPort = FreePortApart(l);
        var listener = new TcpListener(IPAddress.Loopback, targetPort);
        listener.Start(8);

        await using var fleet = TcpPunchFleet.Create(IPAddress.Loopback, l,
            new IPEndPoint(IPAddress.Loopback, targetPort), concurrency: 3, PtpFrameType.THello1);
        var accepted = await AcceptAsync(listener, 3, "对端接受 3 条 connect");

        // 对端在第 2 条连接上送 THello1 → 该连接胜出
        await WriteFramedAsync(accepted[1], Hello1Wire());
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var (winner, _) = await fleet.WaitFrameAsync(cts.Token);
        fleet.Release(winner); // 移出池：销毁时不关
        await fleet.DisposeAsync();

        await winner.SendAsync(Hello1Wire()); // 胜者仍可用（会话承载）
        await AssertEofAsync(accepted[0]);    // 其余 N−1 关闭（02 §5.2④）
        await AssertEofAsync(accepted[2]);
        foreach (var s in accepted) s.Dispose();
    }

    [Fact]
    public async Task 不对称N_目标端口无人监听_等待超时必miss()
    {
        // B 实际落位（N_B=3）：Qbase+2 有监听；A 以 N_A=2 瞄准 Qbase+1——预测基准错位。
        // 三口连续一并探测（qbase=死、qbase+1=死目标、qbase+2=监听位），保证"死端口"前提成立。
        var qbase = FreePort(span: 3);
        var realPort = qbase + 2;
        var listener = new TcpListener(IPAddress.Loopback, realPort);
        listener.Start(4);

        await using var fleet = TcpPunchFleet.Create(IPAddress.Loopback, FreePortApart(qbase, realPort),
            new IPEndPoint(IPAddress.Loopback, qbase + 1), concurrency: 2, PtpFrameType.THello1);
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(1200));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fleet.WaitFrameAsync(cts.Token));
        await UntilAsync(() => fleet.FailedConnects == 2, "两条 connect 均被拒（无监听端口）");
        listener.Stop();
    }
}

/// <summary>Puncher TCP 路径：两段式全链路（N=1 回环 simultaneous open）、N 取 Ack 回填值、超时/探测失败。</summary>
public sealed class PuncherTcpTests
{
    /// <summary>TCP 控制面假缝：探测=回环恒等 NAT（MappedPortShift 模拟端口平移）、0x70/0x76 可编排。</summary>
    private sealed class FakeTcpSeams
    {
        public TaskCompletionSource<EndpointPair> Probed { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource<EndpointPair> Reported { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public ConcurrentQueue<(Guid SessionId, EndpointPair Endpoints)> Reports { get; } = [];
        public Func<Guid, Guid?, string, EndpointPair, CancellationToken, Task<PunchRequestAck>>? RequestHandler;

        /// <summary>探测上报的映射端口 = 本地端口 + 平移量（0=恒等；模拟 SymmetricSequential 下一分配）。</summary>
        public int MappedPortShift;

        /// <summary>默认 Ack 的对端公钥（StartInitiator 校验 65B 未压缩 P-256）。</summary>
        private readonly byte[] _peerPub = EcKeyPair.Generate().ExportPublicKey();

        public string? SeenProto { get; private set; }
        public EndpointPair? SeenRequesterEndpoints { get; private set; }

        public Task<IPEndPoint> TcpProbeAsync(Socket socket, CancellationToken ct)
        {
            var ep = (IPEndPoint)socket.LocalEndPoint!;
            var mapped = new IPEndPoint(IPAddress.Loopback, ep.Port + MappedPortShift);
            socket.Dispose(); // M2-04 契约：探测事务即关，端口 L 由调用方记录复用
            Probed.TrySetResult(new EndpointPair(null,
                new P2P.Core.Protocol.Endpoint(mapped.Address.ToString(), (ushort)mapped.Port)));
            return Task.FromResult(mapped);
        }

        public Task ReportAsync(Guid sessionId, EndpointPair endpoints, CancellationToken ct)
        {
            Reports.Enqueue((sessionId, endpoints));
            Reported.TrySetResult(endpoints);
            return Task.CompletedTask;
        }

        public Task<PunchRequestAck> SendRequestAsync(Guid target, Guid? trigger, string proto,
            EndpointPair requesterEndpoints, CancellationToken ct)
        {
            SeenProto = proto;
            SeenRequesterEndpoints = requesterEndpoints;
            if (RequestHandler is not null) return RequestHandler(target, trigger, proto, requesterEndpoints, ct);
            return Task.FromResult(new PunchRequestAck(0, 0, MsgType.PunchRequest, Guid.NewGuid(),
                new PeerInfo(target, "?", "000000", _peerPub),
                new EndpointPair(null, new P2P.Core.Protocol.Endpoint("127.0.0.1", (ushort)ClosedPort())), 3, false));
        }

        /// <summary>带内探测空闲口（24000-28000）：ack 端点随后的 TCP connect 须真的拒连，
        /// :0 临时段顺序分配易与并行类监听相邻相撞（跨类串扰家族，同 FreePort 迁带缘由）。</summary>
        private static int ClosedPort()
        {
            while (true)
            {
                var port = Random.Shared.Next(24000, 28000);
                var l = new TcpListener(IPAddress.Loopback, port);
                try { l.Start(); }
                catch (SocketException) { continue; }
                l.Stop();
                return port;
            }
        }
    }

    private static Task<IPEndPoint> UdpProbeUnused(Socket socket, CancellationToken ct)
        => Task.FromResult(new IPEndPoint(IPAddress.Loopback, 1)); // TCP 链路不触及 UDP 探测

    private static (Puncher Puncher, FakeTcpSeams Seams) Make(EcKeyPair staticKey,
        int mappedPortShift = 0, PunchOptions? options = null)
    {
        var seams = new FakeTcpSeams { MappedPortShift = mappedPortShift };
        return (new Puncher(seams.SendRequestAsync, seams.ReportAsync, UdpProbeUnused, staticKey,
            options: options, tcpProbe: seams.TcpProbeAsync), seams);
    }

    private static Task<IPEndPoint> BrokenTcpProbe(Socket socket, CancellationToken ct)
        => Task.FromException<IPEndPoint>(new IOException("stun-tcp down"));

    [Fact]
    public async Task TCP两段式全链路_N1_双方握手成功_可互通()
    {
        using var staticA = EcKeyPair.Generate();
        using var staticB = EcKeyPair.Generate();
        var deviceA = Guid.NewGuid();
        var deviceB = Guid.NewGuid();
        var sessionId = Guid.NewGuid();

        var (puncherA, seamsA) = Make(staticA);
        var (puncherB, seamsB) = Make(staticB);
        using (puncherA)
        using (puncherB)
        {
            // A 的 0x70 假缝=模拟服务端：等 B 的 0x76 端点上报后回延后 Ack（N=1 → 目标=对端映射端口+0）
            seamsA.RequestHandler = async (target, trigger, proto, endpoints, ct) =>
            {
                var bReported = await seamsB.Reported.Task;
                return new PunchRequestAck(0, 0, MsgType.PunchRequest, sessionId,
                    new PeerInfo(deviceB, "B", "b00000", staticB.ExportPublicKey()),
                    new EndpointPair(null, bReported.Tcp), PunchCount: 1, RelayAllowed: false);
            };

            var outcomeATask = puncherA.InitiateAsync(deviceB, null, "tcp");

            // B 收邀请（A 端点须 A 已探测）：tcp 槽位在 → TCP 打洞路径
            var aEp = await seamsA.Probed.Task;
            var invite = new PunchInvite(0, 0, MsgType.PunchInvite, sessionId,
                new PeerInfo(deviceA, "A", "a00000", staticA.ExportPublicKey()),
                new EndpointPair(null, aEp.Tcp), PunchCount: 1, false);
            var outcomeB = await puncherB.RespondAsync(invite);
            var outcomeA = await outcomeATask;

            // 双方成功、会话配对、胜出连接四元组交叉一致
            Assert.True(outcomeA.Ok, outcomeA.FailReason);
            Assert.True(outcomeB.Ok, outcomeB.FailReason);
            Assert.Equal(sessionId, outcomeA.SessionId);
            Assert.Equal(sessionId, outcomeB.SessionId);
            Assert.Equal(deviceB, outcomeA.Session!.PeerDeviceId);
            Assert.Equal(deviceA, outcomeB.Session!.PeerDeviceId);
            Assert.Equal(outcomeA.LocalEndpoint!.Port, outcomeB.PeerEndpoint!.Port);
            Assert.Equal(outcomeB.LocalEndpoint!.Port, outcomeA.PeerEndpoint!.Port);

            // 第一段上送：proto=tcp、端点在 tcp 槽位（udp 空）
            Assert.Equal("tcp", seamsA.SeenProto);
            Assert.NotNull(seamsA.SeenRequesterEndpoints!.Tcp);
            Assert.Null(seamsA.SeenRequesterEndpoints.Udp);

            // B 的 0x76：sessionId 正确、tcp 端点（udp 空）
            var (reportedSession, reportedPair) = seamsB.Reports.Single();
            Assert.Equal(sessionId, reportedSession);
            Assert.NotNull(reportedPair.Tcp);
            Assert.Null(reportedPair.Udp);
            Assert.Equal(outcomeB.LocalEndpoint!.Port, reportedPair.Tcp!.Port);

            // 会话互通（PING/PONG 内嵌于 TunnelSession）
            var rtt = await outcomeA.Session!.PingAsync();
            Assert.True(rtt >= TimeSpan.Zero);
            await outcomeA.Session.DisposeAsync();
            await outcomeB.Session!.DisposeAsync();
        }
    }

    [Fact]
    public async Task 目标端口取Ack回填N_N2经平移NAT命中()
    {
        using var staticA = EcKeyPair.Generate();
        using var staticB = EcKeyPair.Generate();
        var deviceA = Guid.NewGuid();
        var deviceB = Guid.NewGuid();
        var sessionId = Guid.NewGuid();

        var (puncherA, seamsA) = Make(staticA);                 // A 恒等 NAT
        var (puncherB, seamsB) = Make(staticB, mappedPortShift: -1); // B 的映射=L−1（下一分配≈L）
        using (puncherA)
        using (puncherB)
        {
            // Ack 回填 N=2：A 须瞄 B 映射端口+1=B 实际 listen 端口才可能命中——
            // 若 A 未用回填 N（如本地缺省 3）则瞄 +2 → 必 miss → 超时失败
            seamsA.RequestHandler = async (target, trigger, proto, endpoints, ct) =>
            {
                var bReported = await seamsB.Reported.Task;
                return new PunchRequestAck(0, 0, MsgType.PunchRequest, sessionId,
                    new PeerInfo(deviceB, "B", "b00000", staticB.ExportPublicKey()),
                    new EndpointPair(null, bReported.Tcp), PunchCount: 2, RelayAllowed: false);
            };

            var outcomeATask = puncherA.InitiateAsync(deviceB, null, "tcp");
            var aEp = await seamsA.Probed.Task;
            var invite = new PunchInvite(0, 0, MsgType.PunchInvite, sessionId,
                new PeerInfo(deviceA, "A", "a00000", staticA.ExportPublicKey()),
                new EndpointPair(null, aEp.Tcp), PunchCount: 2, false);
            var outcomeB = await puncherB.RespondAsync(invite);
            var outcomeA = await outcomeATask;

            Assert.True(outcomeA.Ok, outcomeA.FailReason); // 命中即证明 A 以 Ack 回填 N=2 计算 +1 偏移
            Assert.True(outcomeB.Ok, outcomeB.FailReason);
            await outcomeA.Session!.DisposeAsync();
            await outcomeB.Session!.DisposeAsync();
        }
    }

    [Fact]
    public async Task 目标端口无监听_超时失败()
    {
        using var staticKey = EcKeyPair.Generate();
        var (puncher, seams) = Make(staticKey,
            options: new PunchOptions { PunchTimeout = TimeSpan.FromMilliseconds(1200) });
        using (puncher)
        {
            // 默认假缝回 Ack：对端 tcp 端点=已释放端口，N=3 → +2 偏移处无人监听
            var outcome = await puncher.InitiateAsync(Guid.NewGuid(), null, "tcp");
            Assert.False(outcome.Ok);
            Assert.Equal("punch_timeout", outcome.FailReason);
            Assert.Null(seams.SeenRequesterEndpoints!.Udp); // 端点只在 tcp 槽位
        }
    }

    [Fact]
    public async Task 探测失败_双侧即败_不上报()
    {
        using var staticKey = EcKeyPair.Generate();
        var seams = new FakeTcpSeams();
        var puncher = new Puncher(seams.SendRequestAsync, seams.ReportAsync, UdpProbeUnused, staticKey,
            tcpProbe: BrokenTcpProbe);
        using (puncher)
        {
            var invite = new PunchInvite(0, 0, MsgType.PunchInvite, Guid.NewGuid(),
                new PeerInfo(Guid.NewGuid(), "A", "a00000", staticKey.ExportPublicKey()),
                new EndpointPair(null, new P2P.Core.Protocol.Endpoint("127.0.0.1", 40000)), 3, false);
            var outcome = await puncher.RespondAsync(invite);
            Assert.False(outcome.Ok);
            Assert.Contains("stun_failed", outcome.FailReason);
            Assert.Empty(seams.Reports); // 探测失败不进 0x76

            var initiate = await puncher.InitiateAsync(Guid.NewGuid(), null, "tcp");
            Assert.False(initiate.Ok);
            Assert.Contains("stun_failed", initiate.FailReason);
        }
    }

    [Fact]
    public async Task 未知proto_直接拒绝()
    {
        using var staticKey = EcKeyPair.Generate();
        var (puncher, _) = Make(staticKey);
        using (puncher)
        {
            var outcome = await puncher.InitiateAsync(Guid.NewGuid(), null, "sctp");
            Assert.False(outcome.Ok);
            Assert.Contains("proto_not_supported", outcome.FailReason);
        }
    }
}
