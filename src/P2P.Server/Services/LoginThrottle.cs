using System.Runtime.InteropServices;

namespace P2P.Server.Services;

/// <summary>
/// 登录防爆破参数（SEC-63、07 §11、03 §2.8 login_fail_window_sec/login_delay_cap_ms——
/// AdminSystemApi PUT 联动 Update 即时生效，RelayRateLimiter.UpdateRate 同款双写路径）。
/// </summary>
public sealed class LoginThrottleOptions
{
    /// <summary>login_fail_window_sec：失败计数滑动窗（秒）。</summary>
    public int WindowSec { get; init; } = 900;

    /// <summary>login_delay_cap_ms：递增延迟封顶（毫秒）。</summary>
    public int DelayCapMs { get; init; } = 8000;
}

/// <summary>一次失败计数结果：窗内失败数、本次应答前的阶梯延迟、是否新跨一档（阶跃审计依据）。</summary>
public sealed record ThrottleOutcome(int Fails, int DelayMs, bool SteppedUp);

/// <summary>
/// M5-04 登录防爆破（SEC-63、07 §11）：服务端单例，0x21/0x23/admin login/admin change-password
/// 四入口共用——IP 维跨入口共享同键计数（任一入口失败抬高该 IP 全部入口延迟，第二入口不可独立绕）。
/// 双维：account 维键=username 精确匹配（成功即清零——正常用户复位语义）/ IP 维键=来源地址
/// （成功不清零仅滑窗自然衰减——防同 IP 穿插成功复位绕过）。阶梯=延迟先于凭据校验、
/// min(500ms×2^(fails−1), cap)、fails=0 不延迟（调用方执行延迟；延迟期间正确登录同样受当前档）。
/// 内存态重启清零；键空间上限 8192+60s 空闲清扫（StunGuard 模式）；本类纯计数不写审计——
/// 阶跃记录（login_throttled，≤每窗 5 条/键）由调用方按 SteppedUp 落（携带各自 deviceId 上下文）。
/// </summary>
public sealed class LoginThrottle(LoginThrottleOptions? options = null, TimeProvider? time = null)
{
    /// <summary>account 维（键=username；admin 侧单账户退化为常量 DbInitializer.AdminUsername）。</summary>
    public const string DimAccount = "account";

    /// <summary>IP 维（键=来源 IP 字符串；四入口共享）。</summary>
    public const string DimIp = "ip";

    /// <summary>键数上限：伪造账户/IP 洪泛的字典兜底（超限清 60s 空闲键后仍满则不再记录——同 StunGuard）。</summary>
    private const int KeyCap = 8192;

    /// <summary>单键环形时间戳容量：阶梯只需 5 档，64 足够观测且封顶内存（超出覆盖最旧）。</summary>
    private const int RingCap = 64;

    private readonly TimeProvider _time = time ?? TimeProvider.System;
    private readonly Lock _gate = new();
    private LoginThrottleOptions _options = options ?? new();
    private readonly Dictionary<string, Ring> _rings = [];

    /// <summary>登录尝试前取双维当前档延迟（取大者——两维独立计数同梯生效，A-15 含正确登录）。</summary>
    public int LoginDelayMs(string? username, string? ip)
    {
        lock (_gate)
        {
            var delay = username is null ? 0 : PeekDelayMs(DimAccount, username);
            if (ip is not null)
                delay = Math.Max(delay, PeekDelayMs(DimIp, ip));
            return delay;
        }
    }

    /// <summary>记一次失败（键=dim+":"+值；'account:'/'ip:' 前缀互斥，IP 字符串不可能以 'a:' 开头）。</summary>
    public ThrottleOutcome RecordFailure(string dim, string key)
    {
        lock (_gate)
        {
            var full = $"{dim[0]}:{key}";
            if (_rings.Count >= KeyCap && !_rings.ContainsKey(full))
            {
                var staleBefore = _time.GetLocalNow().UtcTicks - TimeSpan.FromSeconds(60).Ticks;
                foreach (var stale in _rings.Where(kv => kv.Value.LastTicks < staleBefore)
                               .Select(kv => kv.Key).ToList())
                    _rings.Remove(stale);
                if (_rings.Count >= KeyCap) return new ThrottleOutcome(0, 0, false); // 洪泛兜底：不计数不延迟
            }

            var now = _time.GetLocalNow().UtcTicks;
            ref var ring = ref CollectionsMarshal.GetValueRefOrAddDefault(_rings, full, out _);
            ring ??= new Ring();
            ring.Push(now);
            var fails = ring.CountInWindow(now, WindowTicks);
            var delay = DelayFor(fails);
            // 阶跃=延迟值跨档（500→1000→…→cap；达 cap 后同档不再记——每窗 ≤5 条/键，07 §11.3）
            var steppedUp = delay > DelayFor(fails - 1);
            return new ThrottleOutcome(fails, delay, steppedUp);
        }
    }

    /// <summary>成功复位（仅 account 维调用——IP 维成功不清零，07 §11.1）。</summary>
    public void Reset(string dim, string key)
    {
        lock (_gate)
            _rings.Remove($"{dim[0]}:{key}");
    }

    /// <summary>参数热更（AdminSystemApi PUT 联动——运行期即时生效不占 RestartKeys，04 §3）。</summary>
    public void Update(int windowSec, int delayCapMs)
    {
        lock (_gate)
            _options = new LoginThrottleOptions { WindowSec = windowSec, DelayCapMs = delayCapMs };
    }

    private long WindowTicks => (long)Math.Min(_options.WindowSec, 86400) * TimeSpan.TicksPerSecond;

    /// <summary>阶梯：min(500ms×2^(fails−1), cap)；fails≤0 无延迟（07 §11.1）。</summary>
    private int DelayFor(int fails)
    {
        if (fails <= 0) return 0;
        var exp = Math.Min(fails - 1, 24);
        return (int)Math.Min(500L << exp, (long)_options.DelayCapMs);
    }

    private int PeekDelayMs(string dim, string key)
    {
        if (!_rings.TryGetValue($"{dim[0]}:{key}", out var ring)) return 0;
        var now = _time.GetLocalNow().UtcTicks;
        return DelayFor(ring.CountInWindow(now, WindowTicks));
    }

    /// <summary>环形时间戳（满 RingCap 覆盖最旧；LastTicks 供空闲清扫）。</summary>
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
