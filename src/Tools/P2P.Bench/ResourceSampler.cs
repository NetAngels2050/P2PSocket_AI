// M4-05 资源采样（NFR-13）：基准运行期本进程 CPU/内存/句柄周期采样（500ms）。
// in-proc 口径：服务端+双客户端+基准驱动同进程——进程级数值即全栈占用（报告如实标注）。
namespace P2P.Bench;

internal sealed class ResourceSampler : IDisposable
{
    private readonly Csv _csv;
    private readonly System.Diagnostics.Process _proc = System.Diagnostics.Process.GetCurrentProcess();
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _loop;
    private readonly long _startWall = Environment.TickCount64;
    private TimeSpan _lastCpu = TimeSpan.Zero;
    private long _lastCpuWall = Environment.TickCount64;

    public ResourceSampler(Csv csv)
    {
        _csv = csv;
        _loop = Task.Run(SampleLoopAsync);
    }

    private async Task SampleLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                _proc.Refresh();
                var now = Environment.TickCount64;
                var cpu = _proc.TotalProcessorTime;
                // CPU% = 处理器时间增量 / 墙钟增量（单进程口径，多核可 >100%）
                var cpuPct = now > _lastCpuWall
                    ? (cpu - _lastCpu).TotalMilliseconds / (now - _lastCpuWall) * 100.0 : 0;
                _csv.Row(
                    now - _startWall,
                    Math.Round(cpuPct, 1),
                    _proc.WorkingSet64 / 1024.0 / 1024,
                    _proc.PrivateMemorySize64 / 1024.0 / 1024,
                    _proc.HandleCount,
                    _proc.Threads.Count);
                _lastCpu = cpu;
                _lastCpuWall = now;
            }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
            { /* 进程指标瞬态不可得——本轮跳过 */ }
            try { await Task.Delay(500, _cts.Token); }
            catch (OperationCanceledException) { break; }
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        try { _loop.Wait(TimeSpan.FromSeconds(3)); } catch (AggregateException) { }
        _cts.Dispose();
    }
}
