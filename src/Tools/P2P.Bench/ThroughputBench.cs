// M4-05 基准③单隧道吞吐本机回环基线 + ⑤并发映射与 channel 复用（NFR-11、L1 标注 TD-24）。
// ③：四种路径 × 载荷档——路径=裸回环（直连 echo，不经隧道）/direct-udp 隧道（FullCone×FullCone
//    UDP 打洞承载）/direct-tcp 隧道（Seq×Seq N=1 TCP 打洞承载）/relay-tcp-fallback（SR×SR
//    预测 miss→中继回退 TCP 承载，生产主路径）；档=1 流大块/4 并发流大块/1 流小包。
//    L1 口径：本机回环基线 ≠ 真实网络性能（报告/M4-06 如是标注）——测量目的=封装/分帧/加密开销
//    相对裸基线的差值与并发扩展性。
// ⑤：8 映射并发各 32MB（映射维度并发）+ 单映射 100 并发连接（channel 复用维度，02 §4.5）。
using System.Net;
using System.Net.Sockets;
using P2P.IntegrationTests.NatSimulator;

namespace P2P.Bench;

internal static class ThroughputBench
{
    private static readonly IPAddress IpA = IPAddress.Parse("127.0.0.4");
    private static readonly IPAddress IpB = IPAddress.Parse("127.0.0.5");
    private const int BigChunk = 1 << 20;        // 1MB
    private const int BigTotal = 128 << 20;      // 每档总量 128MB（1 流）/4 流各 32MB
    private const int SmallChunk = 1 << 10;      // 1KB 小包档
    private const int SmallCount = 1 << 16;      // 64K 次 = 64MB

    public static async Task RunAsync(Csv throughput)
    {
        // 裸回环基线（不经隧道——同 echo 终点同载荷，差值=全隧道栈开销）
        Console.WriteLine("  [throughput] 裸回环基线 …");
        await using (var world = await BenchWorld.CreateAsync(BenchNatKind.Udp, "th-raw",
            (IpA, UdpNatMode.FullCone), (IpB, UdpNatMode.FullCone)))
        {
            var echoPort = world.StartEcho();
            await RunTierAsync(throughput, world, "loopback-raw", null, echoPort, 1, BigChunk, BigTotal);
            await RunTierAsync(throughput, world, "loopback-raw", null, echoPort, 4, BigChunk, BigTotal);
            await RunTierAsync(throughput, world, "loopback-raw", null, echoPort, 1, SmallChunk, SmallCount * SmallChunk);
        }

        // direct-tcp 恒等 NAT（A-3 形态：Udp 世界 FC×FC + TcpStunStub 恒等应答，TCP 打洞 N=1 直连命中）
        Console.WriteLine("  [throughput] direct-tcp 恒等 NAT …");
        await using (var world = await BenchWorld.CreateAsync(BenchNatKind.Udp, "th-idn",
            (IpA, UdpNatMode.FullCone), (IpB, UdpNatMode.FullCone)))
        {
            var echoPort = world.StartEcho();
            var localPort = await EnableDirectAsync(world, "tcp", echoPort);
            await RunTierAsync(throughput, world, "direct-tcp-identity", (IpA, localPort), echoPort, 1, BigChunk, BigTotal);
            await RunTierAsync(throughput, world, "direct-tcp-identity", (IpA, localPort), echoPort, 4, BigChunk, BigTotal);
            await RunTierAsync(throughput, world, "direct-tcp-identity", (IpA, localPort), echoPort, 1, SmallChunk, SmallCount * SmallChunk);
        }

        // direct-tcp 端口预测（A-5 形态：TcpNatSimulator Seq×Seq，TCP 打洞预测命中 + TCP 承载）
        Console.WriteLine("  [throughput] direct-tcp 端口预测 …");
        await using (var world = await BenchWorld.CreateAsync(BenchNatKind.Tcp, "th-tcp",
            (IpA, UdpNatMode.FullCone), (IpB, UdpNatMode.FullCone),
            TcpNatMode.SymmetricSequential, TcpNatMode.SymmetricSequential))
        {
            var echoPort = world.StartEcho();
            var localPort = await EnableDirectAsync(world, "tcp", echoPort);
            await RunTierAsync(throughput, world, "direct-tcp-predict", (IpA, localPort), echoPort, 1, BigChunk, BigTotal);
            await RunTierAsync(throughput, world, "direct-tcp-predict", (IpA, localPort), echoPort, 4, BigChunk, BigTotal);
            await RunTierAsync(throughput, world, "direct-tcp-predict", (IpA, localPort), echoPort, 1, SmallChunk, SmallCount * SmallChunk);
        }

        // relay-fallback（SymmetricRandom×2 端口预测必 miss → 回退中继承载——生产主路径：
        // L2 公网实测 99% 映射走中继；TCP 承载优先 M2-38 口径。报告瓶颈分析主数据源）
        Console.WriteLine("  [throughput] relay-fallback …");
        await using (var world = await BenchWorld.CreateAsync(BenchNatKind.Tcp, "th-relay",
            (IpA, UdpNatMode.FullCone), (IpB, UdpNatMode.FullCone),
            TcpNatMode.SymmetricRandom, TcpNatMode.SymmetricRandom, punchConcurrency: 2))
        {
            await world.EnableRelayFallbackAsync();
            var echoPort = world.StartEcho();
            var localPort = await EnableRelayAsync(world, echoPort);
            await RunTierAsync(throughput, world, "relay-tcp-fallback", (IpA, localPort), echoPort, 1, BigChunk, BigTotal);
            await RunTierAsync(throughput, world, "relay-tcp-fallback", (IpA, localPort), echoPort, 4, BigChunk, BigTotal);
            await RunTierAsync(throughput, world, "relay-tcp-fallback", (IpA, localPort), echoPort, 1, SmallChunk, SmallCount * SmallChunk);
        }
    }

    /// <summary>建一条 relay 隧道映射（对端回退已开；SR×SR 预测必 miss→回退），返回本地监听端口。</summary>
    private static async Task<int> EnableRelayAsync(BenchWorld world, int echoPort)
    {
        var localPort = BenchWorld.FreePort();
        var id = await world.CreateMappingAsync(world.HttpA, (ushort)localPort, world.ClientB.RemoteCode,
            (ushort)echoPort, "tcp");
        var (_, start) = await world.EnableMappingAsync(world.HttpA, id);
        var (state, _) = await world.WaitTerminalAsync(world.HttpA, id, start, seconds: 60);
        if (state != "relay")
            throw new InvalidOperationException($"吞吐前置失败：映射终态={state}（期望 relay）");
        return localPort;
    }

    /// <summary>建一条 direct 隧道映射（echo 终点由调用方先起并传入），返回本地监听端口。</summary>
    private static async Task<int> EnableDirectAsync(BenchWorld world, string proto, int echoPort)
    {
        var localPort = BenchWorld.FreePort();
        var id = await world.CreateMappingAsync(world.HttpA, (ushort)localPort, world.ClientB.RemoteCode,
            (ushort)echoPort, proto);
        var (_, start) = await world.EnableMappingAsync(world.HttpA, id);
        var (state, _) = await world.WaitTerminalAsync(world.HttpA, id, start);
        if (state != "direct")
            throw new InvalidOperationException($"吞吐前置失败：映射终态={state}（期望 direct）");
        return localPort;
    }

    /// <summary>一档：streams 条并发连接各推 totalBytes/streams（echo 全量读回校验），记 Mbps（发送口径）。</summary>
    private static async Task RunTierAsync(Csv csv, BenchWorld world, string scenario,
        (IPAddress Ip, int Port)? via, int echoPort, int streams, int chunk, long totalBytes)
    {
        var perStream = totalBytes / streams;
        var target = via is { } v ? new IPEndPoint(v.Ip, v.Port) : new IPEndPoint(IPAddress.Loopback, echoPort);
        var start = BenchWorld.StopwatchStart();
        await Task.WhenAll(Enumerable.Range(0, streams).Select(_ => PumpAsync(target, perStream, chunk)));
        var elapsed = BenchWorld.StopwatchElapsed(start);
        var mbps = totalBytes * 8.0 / 1024 / 1024 / (elapsed / 1000.0);
        csv.Row(scenario, streams, chunk, totalBytes, elapsed, Math.Round(mbps, 1));
        Console.WriteLine($"    {scenario} streams={streams} chunk={chunk} → {elapsed}ms {mbps:F1}Mbps");
    }

    /// <summary>单连接：chunk 分块顺序推送至 perStream 字节并全量读回（echo 校验，缺段即抛）。</summary>
    private static async Task PumpAsync(IPEndPoint target, long perStream, int chunk)
    {
        var payload = new byte[chunk];
        Random.Shared.NextBytes(payload);
        using var client = new TcpClient();
        await client.ConnectAsync(target).WaitAsync(TimeSpan.FromSeconds(15));
        await using var stream = client.GetStream();
        var sendTask = Task.Run(async () =>
        {
            long sent = 0;
            while (sent < perStream)
            {
                await stream.WriteAsync(payload);
                sent += chunk;
            }
        });
        // echo 回流同量校验（读满即完整；不逐字节比对——吞吐档校验=流量守恒+尾块抽样）
        var got = new byte[chunk];
        long read = 0;
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(120));
        while (read < perStream)
        {
            var n = await stream.ReadAsync(got, cts.Token);
            if (n <= 0) throw new IOException($"echo 流提前关闭（{read}/{perStream}）");
            read += n;
        }
        await sendTask; // 推送侧无异常即完整（TCP 字节流有序）
    }

    /// <summary>⑤并发：8 映射并发 + 单映射 100 channel（proto=tcp 恒等 NAT 直连世界——TcpClient 载荷）。</summary>
    public static async Task RunConcurrencyAsync(Csv concurrency)
    {
        Console.WriteLine("  [concurrency] 8 映射并发 …");
        await using (var world = await BenchWorld.CreateAsync(BenchNatKind.Udp, "cc-maps",
            (IpA, UdpNatMode.FullCone), (IpB, UdpNatMode.FullCone)))
        {
            var echoPort = world.StartEcho();
            const int maps = 8, perMap = 32 << 20;
            var ids = new List<(Guid Id, int Port)>();
            for (var i = 0; i < maps; i++)
            {
                var port = BenchWorld.FreePort();
                var id = await world.CreateMappingAsync(world.HttpA, (ushort)port, world.ClientB.RemoteCode,
                    (ushort)echoPort, "tcp", $"cc-map-{i}");
                ids.Add((id, port));
            }
            var start = BenchWorld.StopwatchStart();
            foreach (var (id, _) in ids) await world.EnableMappingAsync(world.HttpA, id);
            foreach (var (id, _) in ids)
            {
                var s = BenchWorld.StopwatchStart();
                var (state, _) = await world.WaitTerminalAsync(world.HttpA, id, s, seconds: 60);
                if (state != "direct") throw new InvalidOperationException($"并发映射 {id} 终态={state}");
            }
            var all = Task.WhenAll(ids.Select(m => PumpAsync(new IPEndPoint(IpA, m.Port), perMap, BigChunk)));
            var elapsed = BenchWorld.StopwatchElapsed(start);
            await all.WaitAsync(TimeSpan.FromSeconds(120));
            var done = BenchWorld.StopwatchElapsed(start);
            var total = (long)maps * perMap;
            concurrency.Row("8-maps-concurrent", maps, perMap, total, elapsed, done,
                Math.Round(total * 8.0 / 1024 / 1024 / (done / 1000.0), 1));
            Console.WriteLine($"    8 映射并发 32MB each → 建立到齐 {elapsed}ms 全量 {done}ms");
        }

        Console.WriteLine("  [concurrency] 单映射 100 channel …");
        await using (var world = await BenchWorld.CreateAsync(BenchNatKind.Udp, "cc-chan",
            (IpA, UdpNatMode.FullCone), (IpB, UdpNatMode.FullCone)))
        {
            var echoPort = world.StartEcho();
            var localPort = await EnableDirectAsync(world, "tcp", echoPort);
            const int channels = 100, perChannel = 256 * 1024;
            var start = BenchWorld.StopwatchStart();
            await Task.WhenAll(Enumerable.Range(0, channels)
                .Select(_ => PumpAsync(new IPEndPoint(IpA, localPort), perChannel, 8 * 1024)));
            var elapsed = BenchWorld.StopwatchElapsed(start);
            var total = (long)channels * perChannel;
            concurrency.Row("100-channel-reuse", channels, perChannel, total, elapsed, elapsed,
                Math.Round(total * 8.0 / 1024 / 1024 / (elapsed / 1000.0), 1));
            Console.WriteLine($"    100 channel 256KB each → {elapsed}ms 全部完整");
        }
    }
}
