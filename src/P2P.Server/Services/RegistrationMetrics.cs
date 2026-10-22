using System.Runtime.InteropServices;

namespace P2P.Server.Services;

/// <summary>
/// 注册风暴计数（M5-07/SEC-71、07 §13.1）：register/register_recover 两成功钩子按源 IP 记
/// 环形时间戳（RegistrationService 审计点回调）——AlertPusher register_burst 取窗口快照
/// 聚合（sum=count、前 3 名=topSources）。纯内存观测件：键空间上限 8192+60s 空闲清扫
/// （StunGuard 模式）、重启清零（告警基线随重启重置，与 §11 同口径）。
/// </summary>
public sealed class RegistrationMetrics(TimeProvider? time = null)
{
    /// <summary>键数上限：伪造源洪泛的字典兜底（超限清 60s 空闲键后仍满则不记——同 StunGuard）。</summary>
    private const int KeyCap = 8192;

    /// <summary>单键环形时间戳容量：阈值缺省 5，64 足够观测且封顶内存。</summary>
    private const int RingCap = 64;

    private readonly TimeProvider _time = time ?? TimeProvider.System;
    private readonly Lock _gate = new();
    private readonly Dictionary<string, Ring> _rings = [];

    /// <summary>记一次成功注册（register 或 register_recover）。</summary>
    public void Record(string ip)
    {
        lock (_gate)
        {
            if (_rings.Count >= KeyCap && !_rings.ContainsKey(ip))
            {
                var staleBefore = _time.GetLocalNow().UtcTicks - TimeSpan.FromSeconds(60).Ticks;
                foreach (var stale in _rings.Where(kv => kv.Value.LastTicks < staleBefore)
                               .Select(kv => kv.Key).ToList())
                    _rings.Remove(stale);
                if (_rings.Count >= KeyCap) return; // 洪泛兜底：不记
            }
            var now = _time.GetLocalNow().UtcTicks;
            ref var ring = ref CollectionsMarshal.GetValueRefOrAddDefault(_rings, ip, out _);
            ring ??= new Ring();
            ring.Push(now);
        }
    }

    /// <summary>窗口快照（计数降序）：AlertPusher 聚合消费。</summary>
    public IReadOnlyList<(string Ip, int Count)> SnapshotIpWindow(int windowSec)
    {
        lock (_gate)
        {
            var now = _time.GetLocalNow().UtcTicks;
            var windowTicks = (long)Math.Clamp(windowSec, 1, 86400) * TimeSpan.TicksPerSecond;
            return [.. _rings
                .Select(kv => (Ip: kv.Key, Count: kv.Value.CountInWindow(now, windowTicks)))
                .Where(x => x.Count > 0)
                .OrderByDescending(x => x.Count)];
        }
    }

    /// <summary>环形时间戳（满 RingCap 覆盖最旧；LoginThrottle.Ring 同模式）。</summary>
    private sealed class Ring
    {
        private readonly long[] _ticks = new long[RingCap];
        private int _count;
        private int _head;

        public long LastTicks { get; private set; }

        public void Push(long ticks)
        {
            _ticks[(_head + _count) % RingCap] = ticks;
            if (_count < RingCap) _count++;
            else _head = (_head + 1) % RingCap; // 满：覆盖最旧
            LastTicks = ticks;
        }

        public int CountInWindow(long now, long windowTicks)
        {
            var floor = now - windowTicks;
            var n = 0;
            for (var i = 0; i < _count; i++)
                if (_ticks[(_head + i) % RingCap] > floor) n++;
            return n;
        }
    }
}
