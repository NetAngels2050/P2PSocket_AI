using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Microsoft.EntityFrameworkCore;
using P2P.Core.Protocol;
using P2P.Server.Data;

namespace P2P.Server.Services;

/// <summary>
/// 控制服务监听器（05 §5）：TCP 7000 accept 循环，每连接一个 ControlSession（串行处理）。
/// 纯 I/O 循环不执行业务逻辑（TD-14）；业务由注入的分发器承担（M1-14+ 注册路由）。
/// </summary>
public sealed class ControlServer : IAsyncDisposable
{
    private readonly IDbContextFactory<AppDbContext> _dbFactory;
    private readonly DeviceRegistry _registry;
    private readonly Func<ControlSession, IPcpMessage, Task> _dispatcher;
    private readonly ControlSessionOptions _options;
    private readonly TimeProvider _time;
    private readonly BlacklistStore? _blacklist; // M5-08：accept 闸（07 §13.3）
    private readonly ConcurrentDictionary<ControlSession, byte> _sessions = new(); // 停机时统一关闭
    private readonly Lock _connGate = new();
    private readonly Dictionary<IPAddress, int> _perIpConns = []; // M5-10 §12 单 IP 并发计数
    private int _totalConns; // M5-10 §12 总并发计数

    private TcpListener? _listener;
    private Task? _acceptLoop;
    private int _hmacFailures; // 断连计数（09 §21：HMAC 错误/seq 重复 → 断连计数）

    public ControlServer(IDbContextFactory<AppDbContext> dbFactory, DeviceRegistry registry,
        Func<ControlSession, IPcpMessage, Task> dispatcher,
        ControlSessionOptions? options = null, TimeProvider? time = null,
        BlacklistStore? blacklist = null)
    {
        _dbFactory = dbFactory;
        _registry = registry;
        _dispatcher = dispatcher;
        _options = options ?? new ControlSessionOptions();
        _time = time ?? TimeProvider.System;
        _blacklist = blacklist;
    }

    /// <summary>安全断连累计（HMAC 校验失败/seq 回退；SEC-22 观测）。</summary>
    public int HmacFailureCount => Volatile.Read(ref _hmacFailures);

    /// <summary>当前存活会话（诊断观测）。</summary>
    public IReadOnlyCollection<ControlSession> Sessions => _sessions.Keys.ToArray();

    /// <summary>TCP 监听端点（启动后非空；测试用 127.0.0.1:0 自动分配端口）。</summary>
    public IPEndPoint? LocalEndPoint { get; private set; }

    public Task StartAsync(IPEndPoint endpoint, CancellationToken ct = default)
    {
        var listener = new TcpListener(endpoint);
        listener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        listener.Start(backlog: 64);
        LocalEndPoint = (IPEndPoint)listener.LocalEndpoint!;
        _listener = listener;
        _acceptLoop = Task.Run(() => AcceptLoopAsync(listener, ct), ct);
        return Task.CompletedTask;
    }

    private async Task AcceptLoopAsync(TcpListener listener, CancellationToken ct)
    {
        while (true)
        {
            TcpClient client;
            try
            {
                client = await listener.AcceptTcpClientAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { break; }
            catch (SocketException) { break; }       // Stop 后套接字关闭
            catch (ObjectDisposedException) { break; }
            client.NoDelay = true; // 02 §2.1：控制信道低延迟优先
            // M5-08 IP 黑名单（07 §13.3）：accept 后立即（会话创建前，与 §12 并发闸同点）——立即关闭
            if (_blacklist?.IsBlocked(((IPEndPoint)client.Client.RemoteEndPoint!).Address.ToString()) == true)
            {
                _blacklist.CountHit(BlacklistStore.FaceControl);
                client.Close();
                continue;
            }
            // M5-10 §12 并发闸（黑名单同点、会话创建前）：单 IP/总量任一超限即关——
            // 洪泛下会话表与内存不随连接数无界增长；两键 accept 时现读（控制连接低频，PUT 即时生效）
            var remoteIp = ((IPEndPoint)client.Client.RemoteEndPoint!).Address;
            int perIpMax, totalMax;
            await using (var db = await _dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false))
            {
                var cfg = new ServerConfigStore(db);
                perIpMax = cfg.GetInt("control_conn_max_per_ip");
                totalMax = cfg.GetInt("control_conn_max_total");
            }
            if (!TryAcquireConn(remoteIp, perIpMax, totalMax))
            {
                client.Close();
                continue;
            }
            var session = new ControlSession(client.GetStream(), _dbFactory, _registry, _dispatcher,
                _options, _time, () => Interlocked.Increment(ref _hmacFailures),
                (IPEndPoint)client.Client.RemoteEndPoint!, (IPEndPoint)client.Client.LocalEndPoint!);
            _sessions.TryAdd(session, 0);
            _ = WatchAsync(session, remoteIp); // 读循环自管理生命周期；结束后移出跟踪表+归还配额
        }
    }

    private async Task WatchAsync(ControlSession session, IPAddress remoteIp)
    {
        try { await session.Completion.ConfigureAwait(false); } catch { }
        ReleaseConn(remoteIp); // M5-10 §12：会话结束归还配额（先于移出——Sessions 观测到减员即已归还）
        _sessions.TryRemove(session, out _);
    }

    /// <summary>M5-10 §12 并发闸 try-acquire：单 IP/总量任一达限即拒（超限即关由调用方执行）。</summary>
    private bool TryAcquireConn(IPAddress ip, int perIpMax, int totalMax)
    {
        lock (_connGate)
        {
            if (_totalConns >= totalMax) return false;
            if (_perIpConns.GetValueOrDefault(ip) >= perIpMax) return false;
            _totalConns++;
            _perIpConns[ip] = _perIpConns.GetValueOrDefault(ip) + 1;
            return true;
        }
    }

    /// <summary>M5-10 §12：配额归还（会话结束——键清零即移除，防字典常驻）。</summary>
    private void ReleaseConn(IPAddress ip)
    {
        lock (_connGate)
        {
            _totalConns = Math.Max(0, _totalConns - 1);
            var n = _perIpConns.GetValueOrDefault(ip) - 1;
            if (n <= 0) _perIpConns.Remove(ip); else _perIpConns[ip] = n;
        }
    }

    /// <summary>停止监听并关闭全部在线会话。</summary>
    public async Task StopAsync()
    {
        _listener?.Stop();
        if (_acceptLoop is not null)
            try { await _acceptLoop.ConfigureAwait(false); } catch { }
        foreach (var session in _sessions.Keys)
            await session.CloseAsync("server_stopping").ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync() => await StopAsync().ConfigureAwait(false);
}
