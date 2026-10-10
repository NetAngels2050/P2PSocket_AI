// M4-05 基准⑦服务端并发设备数（NFR-11/13：模拟设备批量注册+稳态心跳 200/500 两档）。
// 设备模拟=真实控制协议客户端 ControlClient（HELLO→0x10 Register→ECIES 解密→Established→
// 5s 心跳自循环）——不拉 ClientRuntime（每 runtime 含 Kestrel Web，非注册/心跳路径关注点）。
// in-proc 口径：服务端与 500 设备模拟同进程（标注进 CSV/summary；真实部署拆进程后网络栈开销另计）。
using System.Diagnostics;
using P2P.Client.Control;
using P2P.Core.Crypto;
using P2P.Core.Protocol;
using P2P.Server;
using P2P.Server.Data;
using P2P.Server.Services;

namespace P2P.Bench;

internal static class DeviceScaleBench
{
    public static async Task RunAsync(Csv deviceScale, int[] tiers)
    {
        foreach (var tier in tiers)
        {
            Console.WriteLine($"  [device-scale] {tier} 设备 …");
            await RunTierAsync(deviceScale, tier);
        }
    }

    private static async Task RunTierAsync(Csv csv, int count)
    {
        var db = new BenchDatabase();
        try
        {
            using (var init = db.Factory.CreateDbContext())
                DbInitializer.Initialize(init);
            // 服务端装配（镜像 BenchWorld.StartServerAsync——无客户端/NAT 的纯控制面世界）
            var registry = new DeviceRegistry();
            var audit = new AuditLogger(db.Factory);
            var signaling = new SignalingCoordinator(db.Factory, registry, new Authorizer(db.Factory), audit);
            var relay = new RelayService(db.Factory, registry, signaling.ResolveRelayPeers);
            var pusher = new DeviceListPusher(db.Factory, registry);
            var router = new ControlMessageRouter(
                new RegistrationService(db.Factory, registry, audit),
                new UserService(db.Factory, audit),
                new GroupService(db.Factory, registry, audit, pusher),
                signaling,
                new MappingService(db.Factory, audit),
                relay,
                new StatsService(db.Factory, audit),
                audit);
            var server = new ControlServer(db.Factory, registry, router.DispatchAsync);
            await server.StartAsync(new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, 0));
            await relay.StartAsync(0, 0);
            var port = ((System.Net.IPEndPoint)server.LocalEndPoint!).Port;

            // 批量注册（并发 50 一批——真实多设备同时上线形态；含 HELLO+Register+ECIES+转建立）
            var clients = new List<ControlClient>(count);
            var proc = Process.GetCurrentProcess();
            proc.Refresh();
            var wsStart = proc.WorkingSet64 / 1024.0 / 1024;
            var registerStart = BenchWorld.StopwatchStart();
            var established = 0;
            const int batchSize = 50;
            for (var offset = 0; offset < count; offset += batchSize)
            {
                var batch = Math.Min(batchSize, count - offset);
                var results = await Task.WhenAll(Enumerable.Range(0, batch).Select(async i =>
                {
                    using var kp = EcKeyPair.Generate();
                    var client = new ControlClient([$"127.0.0.1:{port}"],
                        new ControlClientOptions { HeartbeatInterval = TimeSpan.FromSeconds(5) });
                    try
                    {
                        await client.WaitReadyAsync();
                        var ack = await client.SendRequestAsync<RegisterAck>(seq => new Register(
                            seq, client.TimestampMs(), MsgType.Register,
                            $"BN-{offset + i:000000}", $"bench-{offset + i:000000}", "bench-os", "1.0.0",
                            kp.ExportPublicKey(), null, null, null));
                        var secret = Ecies.Decrypt(kp, ack.DeviceSecretBox);
                        client.CompleteRegistration(ack.DeviceId, secret);
                        return (Ok: true, Client: client);
                    }
                    catch
                    {
                        await client.DisposeAsync();
                        return (Ok: false, Client: null!);
                    }
                }));
                foreach (var (ok, client) in results)
                    if (ok) { clients.Add(client!); established++; }
            }
            var registerMs = BenchWorld.StopwatchElapsed(registerStart);

            // 稳态窗口：3 个心跳周期（5s×3）内采样 CPU%（处理器时间增量/墙钟）+内存
            const int windowSec = 15;
            proc.Refresh();
            var cpuStart = proc.TotalProcessorTime;
            var windowStart = BenchWorld.StopwatchStart();
            await Task.Delay(TimeSpan.FromSeconds(windowSec));
            var cpuPct = proc.TotalProcessorTime.Subtract(cpuStart).TotalMilliseconds
                / BenchWorld.StopwatchElapsed(windowStart) * 100.0;
            proc.Refresh();
            var wsEnd = proc.WorkingSet64 / 1024.0 / 1024;

            csv.Row($"tier-{count}", count, batchSize, registerMs, Math.Round((double)registerMs / count, 1),
                established, windowSec, Math.Round(cpuPct, 1), Math.Round(wsStart, 1), Math.Round(wsEnd, 1));
            Console.WriteLine($"    注册 {registerMs}ms（{established}/{count} 建立） 稳态 {windowSec}s CPU {cpuPct:F1}% WS {wsStart:F0}→{wsEnd:F0}MB");

            // 收尾：先设备后服务端（并发 stop 500 会话与服务端管道 Flush 竞态偶发——收尾异常不吞数据）
            foreach (var c in clients)
            {
                try { await c.DisposeAsync(); }
                catch (Exception ex) when (ex is IOException or ObjectDisposedException) { }
            }
            try
            {
                await relay.DisposeAsync();
                await server.DisposeAsync();
                await signaling.DisposeAsync();
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException) { }
        }
        finally
        {
            db.Dispose();
        }
    }
}
