// M2-16 TCP 打洞（02 §5.2、FR-C-402、TD-10/13、OQ-1/19）：
// - TcpPunchPlan：目标端口偏移纯逻辑（Offsets 扩展点，当前单元素 [N−1]）；
// - TcpPunchFleet：连接池——本地端口 L listen（SO_REUSEADDR；Linux 加 SO_REUSEPORT）+
//   N 条并发 connect（第 1 条沿用 L，其余系统分配不同本地端口避免重复四元组），
//   connect 成功 / listen accept 任一先到均入池；打洞握手由调用方在池上扇出/等待，
//   首个完成帧交换的连接胜出（对端只在收到帧的连接上应答，天然消歧），其余随池销毁关闭。
// 双方对称执行（TCP simultaneous open）：SYN 交叉在两台 NAT 间完成同时打开。
// §5.4 直连优先（2026-10-21）：Create 另收 directTargets（对端映射端点原样 + 对端本机候选）——
// N 条预测 connect **先发**（直连探测后发：避免吞掉本端 NAT 顺序分配端口、污染 +(N−1) 预测基准），
// 随后每个直连目标起独立拒连重试探测（250ms 步进至打洞窗收尾；onConnection 扇出移入
// AddConnection 统一触发——accept 侧连入也即时发 THello1，对端公网/同网段可达时即刻命中）。
using System.Net;
using System.Net.Sockets;
using P2P.Client.Tunnel;
using P2P.Core.Tunnel;

namespace P2P.Client.Punch;

/// <summary>端口预测纯逻辑（02 §5.2：N 条 connect 目标统一为 对端 portTcp+(N−1)；
/// N=1→+0、N=2→+1、N=3（默认）→+2、N=4→+3、N=5→+4 上限）。
/// §5.4 直连优先：偏移 0（对端端点原样）不经此表——由 Puncher 以 directTargets 显式传入 fleet。</summary>
public static class TcpPunchPlan
{
    /// <summary>目标端口偏移表：当前单元素 [N−1]（PRD OQ-1 决议原文）；多偏移扩展点——
    /// 未来返回多元素不改协议，仅本表与 fleet 的 connect 编排变化。</summary>
    public static int[] Offsets(int concurrency) => [concurrency - 1];

    /// <summary>N 条 connect 的统一目标端口（对端 STUN-TCP 映射端口 + 首偏移）。</summary>
    public static int TargetPort(int peerPortTcp, int concurrency) => peerPortTcp + Offsets(concurrency)[0];

    /// <summary>统一目标端点。</summary>
    public static IPEndPoint TargetEndpoint(IPEndPoint peerMapped, int concurrency)
        => new(peerMapped.Address, TargetPort(peerMapped.Port, concurrency));
}

/// <summary>
/// TCP 打洞连接池：构造即启动 listen(L) + N 并发 connect；连接建立（任一路径）即包装为
/// <see cref="TcpFrameTransport"/> 入池并启动接收泵，泵在帧类型命中 <paramref name="awaitedFrameType"/>
/// 时完成 <see cref="WaitFrameAsync"/>。调用方取首帧后 <see cref="Release"/> 胜出连接、销毁池关闭其余。
/// </summary>
internal sealed class TcpPunchFleet : IAsyncDisposable
{
    private sealed record Pooled(TcpFrameTransport Transport, Task Pump);

    private readonly byte _awaitedType;
    private readonly CancellationTokenSource _cts = new();
    private readonly TaskCompletionSource<(TcpFrameTransport Transport, byte[] Frame)> _first =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly object _gate = new();
    private readonly Dictionary<TcpFrameTransport, Pooled> _pool = [];
    private readonly List<Task> _connects = [];
    private readonly Func<TcpFrameTransport, ValueTask>? _onConnection; // 入池即扇出（connect/accept/直连探测统一）
    private Socket? _listener;
    private Task? _acceptLoop;
    private TcpFrameTransport? _released;
    private int _failedConnects;
    private int _directRefused;
    private int _firstConnectLocalPort;
    private int _disposed;

    /// <summary>直连探测拒连（RST）重试步进（§5.4：对端 listen 口晚就绪的竞态窗口覆盖）。</summary>
    public static readonly TimeSpan DirectRetryInterval = TimeSpan.FromMilliseconds(250);

    private TcpPunchFleet(byte awaitedType, Func<TcpFrameTransport, ValueTask>? onConnection)
    {
        _awaitedType = awaitedType;
        _onConnection = onConnection;
    }

    /// <summary>
    /// 建池：本地端口 L listen + N 条并发 connect（第 1 条沿用 L、其余系统分配），
    /// 随后对 directTargets 各起一条**拒连重试**的直连探测（§5.4：预测 connect 先发，
    /// 直连探测后发——不吞本端 NAT 顺序分配端口、保 +(N−1) 预测基准）。
    /// </summary>
    /// <param name="onConnection">连接入池即回调（connect 成功/listen accept/直连探测命中统一触发；
    /// 发起方在其上扇出 THello1；尽力而为，异常不阻断）。</param>
    public static TcpPunchFleet Create(IPAddress? bindAddress, int localPortL, IPEndPoint target,
        IReadOnlyList<IPEndPoint>? directTargets, int concurrency, byte awaitedFrameType,
        Func<TcpFrameTransport, ValueTask>? onConnection = null)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(concurrency, 1);
        var fleet = new TcpPunchFleet(awaitedFrameType, onConnection);

        // a. 本地端口 L listen（02 §5.2③a：SO_REUSEADDR；Linux 加 SO_REUSEPORT）
        var listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        SetPunchReuse(listener);
        listener.Bind(new IPEndPoint(bindAddress ?? IPAddress.Any, localPortL));
        listener.Listen(concurrency + 2);
        fleet._listener = listener;
        fleet._acceptLoop = fleet.AcceptLoopAsync();

        // b. N 条并发 connect：目标统一 portTcp+(N−1)；第 1 条 bind L，其余 bind 0（不同本地端口，
        //    避免同源端口×同目标端口的重复四元组被 OS 拒绝——02 §5.2 实现备注）
        for (var i = 0; i < concurrency; i++)
        {
            var s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            SetPunchReuse(s);
            s.Bind(new IPEndPoint(bindAddress ?? IPAddress.Any, i == 0 ? localPortL : 0));
            if (i == 0) fleet._firstConnectLocalPort = ((IPEndPoint)s.LocalEndPoint!).Port;
            fleet._connects.Add(fleet.ConnectOneAsync(s, target));
        }

        // c. 直连探测（§5.4）：每目标独立拒连重试（bind 0；成功即入池扇出）
        if (directTargets is not null)
            foreach (var t in directTargets)
                fleet._connects.Add(fleet.DirectProbeAsync(bindAddress, t));
        return fleet;
    }

    /// <summary>等待首个命中帧类型的连接与帧（超时/取消由调用方 ct 控制 → punch_timeout）。</summary>
    public Task<(TcpFrameTransport Transport, byte[] Frame)> WaitFrameAsync(CancellationToken ct)
        => _first.Task.WaitAsync(ct);

    /// <summary>胜出连接移出池（销毁池时不关闭，移交会话）。</summary>
    public TcpFrameTransport Release(TcpFrameTransport winner)
    {
        lock (_gate) _pool.Remove(winner);
        _released = winner;
        return winner;
    }

    /// <summary>当前池内连接快照（发起方周期扇出用）。</summary>
    public IReadOnlyList<TcpFrameTransport> Connections
    {
        get { lock (_gate) return [.. _pool.Keys]; }
    }

    /// <summary>诊断：池内活跃连接数。</summary>
    public int LiveConnections
    {
        get { lock (_gate) return _pool.Count; }
    }

    /// <summary>诊断：第 1 条 connect 的本地端口（须=端口 L，02 §5.2③b）。</summary>
    public int FirstConnectLocalPort => _firstConnectLocalPort;

    /// <summary>诊断：失败（拒连/超时）的 connect 条数（不含直连探测——见 <see cref="DirectRefused"/>）。</summary>
    public int FailedConnects => Volatile.Read(ref _failedConnects);

    /// <summary>诊断：直连探测累计拒连（RST）次数（§5.4；重试计数，与预测 connect 失败分账）。</summary>
    public int DirectRefused => Volatile.Read(ref _directRefused);

    private async Task ConnectOneAsync(Socket s, IPEndPoint target)
    {
        try
        {
            await s.ConnectAsync(target, _cts.Token);
            await FanOutAsync(AddConnection(s));
        }
        catch
        {
            s.Dispose();
            Interlocked.Increment(ref _failedConnects);
        }
    }

    /// <summary>直连探测（§5.4）：拒连（RST=端口未就绪/无人监听）时按步进重试至打洞窗收尾；
    /// 成功即入池扇出。DROP 型丢弃由 OS 级 SYN 重传覆盖（不出 SocketException 不重试）。</summary>
    private async Task DirectProbeAsync(IPAddress? bindAddress, IPEndPoint target)
    {
        while (Volatile.Read(ref _disposed) == 0)
        {
            var s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                SetPunchReuse(s);
                s.Bind(new IPEndPoint(bindAddress ?? IPAddress.Any, 0));
                await s.ConnectAsync(target, _cts.Token);
                await FanOutAsync(AddConnection(s));
                return;
            }
            catch (SocketException)
            {
                s.Dispose();
                Interlocked.Increment(ref _directRefused);
                try { await Task.Delay(DirectRetryInterval, _cts.Token); }
                catch (OperationCanceledException) { return; }
            }
            catch (OperationCanceledException) { s.Dispose(); return; } // 打洞窗收尾/池销毁
            catch { s.Dispose(); return; } // 其他异常：放弃该目标（打洞路径不受影响）
        }
    }

    /// <summary>入池即扇出（§5.4：connect/accept/直连探测统一；尽力而为，异常不阻断）。</summary>
    private async ValueTask FanOutAsync(TcpFrameTransport? transport)
    {
        if (transport is null || _onConnection is null) return;
        try { await _onConnection(transport); }
        catch { /* 扇出首帧尽力而为（连接瞬断等），周期补发兜底 */ }
    }

    private async Task AcceptLoopAsync()
    {
        var listener = _listener!;
        try
        {
            while (!_cts.IsCancellationRequested)
            {
                var s = await listener.AcceptAsync(_cts.Token);
                await FanOutAsync(AddConnection(s));
            }
        }
        catch { /* 停机关闭/取消：出池路径由 Dispose 收尾 */ }
    }

    /// <summary>连接入池（listen accept / connect 成功对称入池）；建池已停则即弃。</summary>
    private TcpFrameTransport? AddConnection(Socket s)
    {
        TcpFrameTransport transport;
        lock (_gate)
        {
            if (Volatile.Read(ref _disposed) == 1)
            {
                s.Dispose();
                return null;
            }
            transport = new TcpFrameTransport(s);
            var pooled = new Pooled(transport, PumpAsync(transport));
            _pool[transport] = pooled;
        }
        return transport;
    }

    /// <summary>接收泵：循环读帧，命中 <see cref="_awaitedType"/> 完成首帧任务；关闭/异常出池。</summary>
    private async Task PumpAsync(TcpFrameTransport transport)
    {
        try
        {
            while (true)
            {
                var frame = await transport.ReceiveAsync(_cts.Token);
                if (frame is null) break; // 对端关闭
                if (PtpFrameCodec.ParseHeader(frame).Type == _awaitedType)
                {
                    _first.TrySetResult((transport, frame));
                    return; // 胜出连接移交调用方，泵退位
                }
                // 非等待帧（对端重复扇出的握手帧等）丢弃继续
            }
        }
        catch { /* 取消/异常：出池 */ }
        lock (_gate) _pool.Remove(transport);
        try { await transport.DisposeAsync(); } catch { /* 已释放 */ }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1) return;
        List<Pooled> pooled;
        lock (_gate)
        {
            pooled = [.. _pool.Values];
            _pool.Clear();
        }
        _listener?.Dispose(); // accept 循环随之退出
        await _cts.CancelAsync();
        foreach (var p in pooled)
            if (p.Transport != _released)
                try { await p.Transport.DisposeAsync(); } catch { /* 收尾尽力而为 */ }
        foreach (var t in _connects) { try { await t; } catch { /* 取消路径 */ } }
        if (_acceptLoop is not null) { try { await _acceptLoop; } catch { } }
        foreach (var p in pooled)
            if (p.Transport != _released)
                try { await p.Pump; } catch { }
        _cts.Dispose();
    }

    /// <summary>打洞 socket 端口复用（02 §5.2 实现备注：Windows SO_REUSEADDR；
    /// Linux 需 SO_REUSEADDR + SO_REUSEPORT——listen(L) 与 connect#1(L) 同端口并存）。</summary>
    internal static void SetPunchReuse(Socket socket)
    {
        socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        if (OperatingSystem.IsLinux())
        {
            try { socket.SetSocketOption(SocketOptionLevel.Socket, (SocketOptionName)0x0F, true); }
            catch (SocketException) { /* SO_REUSEPORT=15 非所有内核可用 */ }
        }
    }
}
