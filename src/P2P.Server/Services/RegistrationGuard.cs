using System.Net;
using System.Runtime.InteropServices;

namespace P2P.Server.Services;

/// <summary>
/// 注册准入闸② 单 IP 频控参数（07 §5.1、03 §2.8 register_rate_per_ip——启动期读库，改值须重启）。
/// </summary>
public sealed class RegistrationGuardOptions
{
    /// <summary>register_rate_per_ip：单 IP 注册频控（次/小时/IP，容量=速率、初始满桶）。</summary>
    public int PerHour { get; init; } = 10;
}

/// <summary>
/// M5-02 注册准入闸②：单 IP 令牌桶（SEC-61、07 §5.1）——StunGuard TakeNoLock 同款
/// （TimeProvider 计时、容量=速率、初始满桶；键空间上限 8192+60s 空闲清扫），仅速率单位为次/小时。
/// 键=控制连接源 IP；闸①开关/闸③总量在 RegistrationService 查库，不入本类。
/// </summary>
public sealed class RegistrationGuard(RegistrationGuardOptions? options = null, TimeProvider? time = null)
{
    /// <summary>单 IP 桶数上限：伪造源洪泛的字典兜底（超限清 60s 空闲桶后仍满则拒新源——同 StunGuard）。</summary>
    private const int IpBucketCap = 8192;

    private readonly RegistrationGuardOptions _options = options ?? new();
    private readonly TimeProvider _time = time ?? TimeProvider.System;
    private readonly Lock _gate = new();
    private readonly Dictionary<IPAddress, Bucket> _buckets = [];

    /// <summary>闸②：注册尝试前取一枚令牌（新建与覆盖式恢复同耗——同为滥用面）。</summary>
    public bool TryAcquire(IPAddress ip)
    {
        lock (_gate)
        {
            if (_buckets.Count >= IpBucketCap && !_buckets.ContainsKey(ip))
            {
                var staleBefore = _time.GetLocalNow().UtcTicks - TimeSpan.FromSeconds(60).Ticks;
                foreach (var stale in _buckets.Where(kv => kv.Value.LastTicks < staleBefore)
                               .Select(kv => kv.Key).ToList())
                    _buckets.Remove(stale);
                if (_buckets.Count >= IpBucketCap) return false;
            }

            var now = _time.GetLocalNow().UtcTicks;
            ref var bucket = ref CollectionsMarshal.GetValueRefOrAddDefault(_buckets, ip, out _);
            bucket ??= new Bucket(_options.PerHour, now); // 初始满桶
            bucket.Tokens = Math.Min(_options.PerHour,
                bucket.Tokens + (now - bucket.LastTicks) * _options.PerHour
                / (double)TimeSpan.TicksPerHour);
            bucket.LastTicks = now;
            if (bucket.Tokens < 1) return false;
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
