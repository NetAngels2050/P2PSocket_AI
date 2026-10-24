using System.Runtime.CompilerServices;

namespace P2P.Server.Tests;

/// <summary>CI 小核跑机线程池饥饿治理（2026-10-24 维护期）：Microsoft.Data.Sqlite 为同步
/// I/O（EF 的 async 包装底层仍阻塞池线程），xUnit 类并行下 2 核 runner 的默认线程池
/// （minThreads=CPU 数、超出后注入 ~1 线程/秒）可被同步 SQLite 调用瞬时占满——异步续体
/// （如 0x71 PunchInvite 转发链上的 await 续体）排队等待新线程注入，实证形态=正路径应答
/// 整窗超时（5s/15s 击穿家族散布多个不相干测试类，Signaling/Stats/Relay/CompletePunch 同型；
/// 本地多核从不饥饿故全绿）。抬高最小线程数消除注入延迟——仅测试进程生效，不影响生产。</summary>
internal static class ThreadPoolInit
{
    [ModuleInitializer]
    internal static void Configure()
    {
        var min = Math.Max(32, Environment.ProcessorCount * 4);
        ThreadPool.SetMinThreads(min, min);
    }
}
