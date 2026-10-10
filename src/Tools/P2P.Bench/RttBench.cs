// M4-05 基准④新增延迟（NFR-11：PTP PING RTT vs 回环基线差值=封装加密开销；直连/中继分别测量）。
// 五口径各取样本（同机同时段消除系统噪声）：
//   - ptp-ping / ptp-ping-relay：POST /api/diagnostics/ping-device（PTP PING，隧道层 02 §4）
//     N 轮取 API 自报 avg/min/max——直连（FC×FC UDP 打洞）与中继（SR×SR 预测 miss→回退）两世界；
//   - tunnel-echo / relay-echo：经虚拟 IP 的 TCP 连接内 64B 往返（同隧道同承载的 TCP+封栈口径）；
//   - loopback-echo：裸回环 TCP 连接内 64B 往返（基线）。
// L1 标注：回环 RTT 常亚毫秒，差值口径=开销放大后的相对量（M4-06 报告换算每跳开销）。
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using P2P.IntegrationTests.NatSimulator;

namespace P2P.Bench;

internal static class RttBench
{
    private static readonly IPAddress IpA = IPAddress.Parse("127.0.0.4");
    private static readonly IPAddress IpB = IPAddress.Parse("127.0.0.5");

    public static async Task RunAsync(Csv ping, Csv rtt, int pingRounds = 20, int echoSamples = 200)
    {
        // ── 直连世界（FullCone×FullCone UDP 打洞 direct）───────────────────
        await using (var world = await BenchWorld.CreateAsync(BenchNatKind.Udp, "rtt",
            (IpA, UdpNatMode.FullCone), (IpB, UdpNatMode.FullCone)))
        {
            var echoPort = world.StartEcho();
            var localPort = BenchWorld.FreePort();
            var id = await world.CreateMappingAsync(world.HttpA, (ushort)localPort, world.ClientB.RemoteCode,
                (ushort)echoPort, "tcp");
            var (_, start) = await world.EnableMappingAsync(world.HttpA, id);
            var (state, _) = await world.WaitTerminalAsync(world.HttpA, id, start);
            if (state != "direct")
                throw new InvalidOperationException($"RTT 前置失败：映射终态={state}（期望 direct）");

            // ① PTP PING（API 每轮内部 sent=4，取自报 avg/min/max）
            await PingRoundsAsync(ping, world, "ptp-ping", pingRounds);

            // ② 经直连隧道 TCP echo 64B 往返（单连接串行——连接级 RTT 样本）
            await EchoRoundtripSamplesAsync(rtt, "tunnel-echo", new IPEndPoint(IpA, localPort), echoSamples);

            // ③ 裸回环 TCP echo 64B 往返（基线）
            await EchoRoundtripSamplesAsync(rtt, "loopback-echo", new IPEndPoint(IPAddress.Loopback, echoPort), echoSamples);
        }

        // ── 中继世界（SymmetricRandom×2 端口预测必 miss → 回退；NFR-11"中继分别测量"，
        //    亦即 L2 生产主路径——公网实测 99% 映射走中继承载）─────────────────
        await using (var world = await BenchWorld.CreateAsync(BenchNatKind.Tcp, "rtt-relay",
            (IpA, UdpNatMode.FullCone), (IpB, UdpNatMode.FullCone),
            TcpNatMode.SymmetricRandom, TcpNatMode.SymmetricRandom, punchConcurrency: 2))
        {
            await world.EnableRelayFallbackAsync();
            var echoPort = world.StartEcho();
            var localPort = BenchWorld.FreePort();
            var id = await world.CreateMappingAsync(world.HttpA, (ushort)localPort, world.ClientB.RemoteCode,
                (ushort)echoPort, "tcp");
            var (_, start) = await world.EnableMappingAsync(world.HttpA, id);
            var (state, _) = await world.WaitTerminalAsync(world.HttpA, id, start, seconds: 60);
            if (state != "relay")
                throw new InvalidOperationException($"RTT 中继前置失败：映射终态={state}（期望 relay）");

            // ④ 中继承载 PTP PING（viaRelay=true 断言进 CSV 数据）
            await PingRoundsAsync(ping, world, "ptp-ping-relay", pingRounds);

            // ⑤ 经中继隧道 TCP echo 64B 往返
            await EchoRoundtripSamplesAsync(rtt, "relay-echo", new IPEndPoint(IpA, localPort), echoSamples);
        }
    }

    private static async Task PingRoundsAsync(Csv ping, BenchWorld world, string scenario, int rounds)
    {
        Console.WriteLine($"  [rtt] {scenario} ×{rounds} 轮 …");
        for (var i = 1; i <= rounds; i++)
        {
            var resp = await world.PostAsync(world.HttpA, "/api/diagnostics/ping-device",
                new { remoteCode = world.ClientB.RemoteCode });
            if (resp.GetProperty("code").GetInt32() != 0)
                throw new InvalidOperationException($"{scenario} 失败：{resp.GetProperty("msg")}");
            var data = resp.GetProperty("data");
            ping.Row(scenario, i,
                data.GetProperty("minMs").GetInt64(),
                data.GetProperty("avgMs").GetDouble(),
                data.GetProperty("maxMs").GetInt64(),
                data.GetProperty("received").GetInt32(),
                data.GetProperty("viaRelay").GetBoolean());
        }
    }

    private static async Task EchoRoundtripSamplesAsync(Csv rtt, string scenario, IPEndPoint target, int samples)
    {
        Console.WriteLine($"  [rtt] {scenario} ×{samples} …");
        var payload = new byte[64];
        var got = new byte[64];
        using var client = new TcpClient();
        await client.ConnectAsync(target).WaitAsync(TimeSpan.FromSeconds(15));
        await using var stream = client.GetStream();
        for (var i = 1; i <= samples; i++)
        {
            // Stopwatch 微秒精度（回环 RTT 亚毫秒——TickCount64 毫秒粒度会大量取整为 0，
            // 差值口径失真；报告基线表需要可信的相对开销）
            var sw = System.Diagnostics.Stopwatch.StartNew();
            await stream.WriteAsync(payload);
            var offset = 0;
            while (offset < got.Length)
            {
                var n = await stream.ReadAsync(got);
                if (n <= 0) throw new IOException($"{scenario} 流提前关闭");
                offset += n;
            }
            sw.Stop();
            rtt.Row(scenario, i, Math.Round(sw.Elapsed.TotalMilliseconds, 3));
        }
    }
}
