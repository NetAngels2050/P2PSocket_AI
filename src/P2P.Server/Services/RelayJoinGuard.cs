using System.Net;
using System.Runtime.InteropServices;

namespace P2P.Server.Services;

/// <summary>
/// M5-10/SEC-64 监听面资源上限：中继 JOIN 单 IP 到达速率令牌桶（07 §12、03 §2.8
/// relay_join_rate_per_ip——运行期现读即时生效，速率逐次传入）。RegistrationGuard/
/// StunGuard TakeNoLock 同款（TimeProvider 计时、容量=速率、初始满桶；键空间上限
/// 8192+60s 空闲清扫），仅速率单位为次/秒。键=中继承载源 IP（UDP 到达与 TCP 首帧
/// JOIN 同源同桶）；数据帧与 KEEPALIVE 不扣桶——只闸会话建立面（07 §12）。
/// </summary>
public sealed class RelayJoinGuard(TimeProvider? time = null)
{
    /// <summary>单 IP 桶数上限：伪造源洪泛的字典兜底（超限清 60s 空闲桶后仍满则拒新源——同 StunGuard）。</summary>
    private const int IpBucketCap = 8192;

    private readonly TimeProvider _time = time ?? TimeProvider.System;
    private readonly Lock _gate = new();
    private readonly Dictionary<IPAddress, Bucket> _buckets = [];
    private long _dropped; // 限流丢弃累计（观测与测试断言——重启清零，内存态同告警基线口径）

    /// <summary>JOIN 被限流丢弃累计。</summary>
    public long Dropped => Volatile.Read(ref _dropped);

    /// <summary>闸：JOIN 解析/认领前扣一枚令牌（rate=relay_join_rate_per_ip 现值——容量与补充同速率）。</summary>
    public bool TryAcquire(IPAddress ip, int ratePerSec)
    {
        lock (_gate)
        {
            if (_buckets.Count >= IpBucketCap && !_buckets.ContainsKey(ip))
            {
                var staleBefore = _time.GetLocalNow().UtcTicks - TimeSpan.FromSeconds(60).Ticks;
                foreach (var stale in _buckets.Where(kv => kv.Value.LastTicks < staleBefore)
                               .Select(kv => kv.Key).ToList())
                    _buckets.Remove(stale);
                if (_buckets.Count >= IpBucketCap) { _dropped++; return false; }
            }

            var now = _time.GetLocalNow().UtcTicks;
            ref var bucket = ref CollectionsMarshal.GetValueRefOrAddDefault(_buckets, ip, out _);
            bucket ??= new Bucket(ratePerSec, now); // 初始满桶
            bucket.Tokens = Math.Min(ratePerSec,
                bucket.Tokens + (now - bucket.LastTicks) * ratePerSec
                / (double)TimeSpan.TicksPerSecond);
            bucket.LastTicks = now;
            if (bucket.Tokens < 1) { _dropped++; return false; }
            bucket.Tokens -= 1;
            return true;
        }
    }

    private sealed class Bucket(double tokens, long lastTicks)
    {
        public double Tokens = tokens;
        public long LastTicks = lastTicks;
    }
}
