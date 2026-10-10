// M4-05 基准①打洞成功率矩阵 + ②建立耗时分布（NFR-11/14、09 §3、A-5 矩阵扩展）。
// ①矩阵：UDP 侧=UdpNatMode 组合（cone 家族+symmetric 两型 5×5 全组合+UdpBlocked 代表对 2 格；
//    UDP 打洞无端口预测，N 列恒 1——THello 连发 10ms×20 固定口径 02 §5.1）；TCP 侧=Seq/Random
//    4 组合 × N=1~5（端口预测并发口径 02 §5.2，A-5 扩展为全组合）。每格独立世界+独立映射样本，
//    中继回退全程开（矩阵含回退率：direct/relay/failed 三态）+服务端 punch_stats 0x72 交叉列。
// ②耗时：direct（FullCone×FullCone UDP 承载）与 relay（SymmetricRandom×2 TCP 承载+回退）两世界
//    各 50 独立世界样本（每样本全新世界——隧道/会话零残留，enable→终态墙钟即纯建立路径；
//    轮询粒度 200ms 计入口径）。
using System.Net;
using P2P.IntegrationTests.NatSimulator;

namespace P2P.Bench;

internal static class PunchMatrixBench
{
    private static readonly IPAddress IpA = IPAddress.Parse("127.0.0.4");
    private static readonly IPAddress IpB = IPAddress.Parse("127.0.0.5");

    /// <summary>UDP 矩阵模式集（UdpBlocked 以代表对单列——全 6×6 含 11 个 UdpBlocked 格，
    /// 其语义均为"UDP 出站全丢→miss→TCP 中继承载"，信息量不随对端模式变化）。</summary>
    private static readonly UdpNatMode[] UdpModes =
    [
        UdpNatMode.FullCone, UdpNatMode.RestrictedCone, UdpNatMode.PortRestricted,
        UdpNatMode.SymmetricRandom, UdpNatMode.SymmetricSequential,
    ];

    public static async Task RunMatrixAsync(Csv matrix, string outDir)
    {
        // ── UDP 矩阵（proto=udp：映射承载与打洞同走 UDP 路径）──────────────
        foreach (var modeA in UdpModes)
            foreach (var modeB in UdpModes)
                await RunCellAsync(matrix, BenchNatKind.Udp, modeA, modeB, n: 1, proto: "udp");
        // UdpBlocked 代表对（发起侧/目标侧各一）
        await RunCellAsync(matrix, BenchNatKind.Udp, UdpNatMode.UdpBlocked, UdpNatMode.FullCone, 1, "udp");
        await RunCellAsync(matrix, BenchNatKind.Udp, UdpNatMode.FullCone, UdpNatMode.UdpBlocked, 1, "udp");

        // ── TCP 矩阵（proto=tcp：端口预测 N=1~5 全组合）───────────────────
        foreach (var modeA in new[] { TcpNatMode.SymmetricSequential, TcpNatMode.SymmetricRandom })
            foreach (var modeB in new[] { TcpNatMode.SymmetricSequential, TcpNatMode.SymmetricRandom })
                for (var n = 1; n <= 5; n++)
                    await RunCellAsync(matrix, BenchNatKind.Tcp,
                        UdpNatMode.FullCone, UdpNatMode.FullCone, n, "tcp",
                        tcpModeA: modeA, tcpModeB: modeB);
    }

    /// <summary>单格：独立世界 → A 侧对 B 开回退 → echo → 建映射 enable → 等终态 → 0x72 交叉取数。</summary>
    private static async Task RunCellAsync(Csv matrix, BenchNatKind kind, UdpNatMode modeA, UdpNatMode modeB,
        int n, string proto, TcpNatMode tcpModeA = TcpNatMode.SymmetricSequential,
        TcpNatMode tcpModeB = TcpNatMode.SymmetricSequential)
    {
        var natA = kind == BenchNatKind.Udp ? modeA.ToString() : tcpModeA.ToString();
        var natB = kind == BenchNatKind.Udp ? modeB.ToString() : tcpModeB.ToString();
        Console.WriteLine($"  [matrix] {proto} {natA}×{natB} N={n} …");
        await using var world = await BenchWorld.CreateAsync(kind, $"mx-{proto}-{natA}-{natB}-{n}",
            (IpA, modeA), (IpB, modeB), tcpModeA, tcpModeB, punchConcurrency: n);
        await world.EnableRelayFallbackAsync();

        var echoPort = world.StartEcho();
        var localPort = BenchWorld.FreePort();
        var id = await world.CreateMappingAsync(world.HttpA, (ushort)localPort, world.ClientB.RemoteCode,
            (ushort)echoPort, proto);
        var (_, start) = await world.EnableMappingAsync(world.HttpA, id);
        var (state, elapsed) = await world.WaitTerminalAsync(world.HttpA, id, start);
        var stats = await world.PunchStatsAsync();
        var cross = string.Join(";", stats.OrderBy(kv => kv.Key).Select(kv => $"{kv.Key}={kv.Value}"));
        matrix.Row(proto, natA, natB, n, state, elapsed, cross);
        Console.WriteLine($"    → {state} {elapsed}ms punch_stats[{cross}]");
    }

    /// <summary>②建立耗时：target=direct/relay 各 50 独立世界样本（enable→终态墙钟）。</summary>
    public static async Task RunLatencyAsync(Csv latency, string target, int samples)
    {
        for (var i = 1; i <= samples; i++)
        {
            if (target == "direct")
            {
                Console.WriteLine($"  [punch-latency:{target}] 样本 {i}/{samples} …");
                await using var world = await BenchWorld.CreateAsync(BenchNatKind.Udp, $"pl-d-{i}",
                    (IpA, UdpNatMode.FullCone), (IpB, UdpNatMode.FullCone));
                var echoPort = world.StartEcho();
                var localPort = BenchWorld.FreePort();
                var id = await world.CreateMappingAsync(world.HttpA, (ushort)localPort,
                    world.ClientB.RemoteCode, (ushort)echoPort, "udp");
                var (_, start) = await world.EnableMappingAsync(world.HttpA, id);
                var (state, elapsed) = await world.WaitTerminalAsync(world.HttpA, id, start);
                latency.Row(target, i, state, elapsed);
                Console.WriteLine($"    → {state} {elapsed}ms");
            }
            else
            {
                Console.WriteLine($"  [punch-latency:{target}] 样本 {i}/{samples} …");
                await using var world = await BenchWorld.CreateAsync(BenchNatKind.Tcp, $"pl-r-{i}",
                    (IpA, UdpNatMode.FullCone), (IpB, UdpNatMode.FullCone),
                    TcpNatMode.SymmetricRandom, TcpNatMode.SymmetricRandom, punchConcurrency: 2);
                await world.EnableRelayFallbackAsync();
                var echoPort = world.StartEcho();
                var localPort = BenchWorld.FreePort();
                var id = await world.CreateMappingAsync(world.HttpA, (ushort)localPort,
                    world.ClientB.RemoteCode, (ushort)echoPort, "tcp");
                var (_, start) = await world.EnableMappingAsync(world.HttpA, id);
                var (state, elapsed) = await world.WaitTerminalAsync(world.HttpA, id, start, seconds: 60);
                latency.Row(target, i, state, elapsed);
                Console.WriteLine($"    → {state} {elapsed}ms");
            }
        }
    }
}
