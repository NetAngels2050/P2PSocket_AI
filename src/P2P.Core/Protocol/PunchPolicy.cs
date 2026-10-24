namespace P2P.Core.Protocol;

/// <summary>
/// 打洞并发路数 N 的协议级约束（OQ-1/OQ-19/TD-20：1~5，缺省 3）。
/// 客户端 settings 校验与服务端 0x70 校验回填共用同一口径（AI-11 单一事实来源）。
/// </summary>
public static class PunchPolicy
{
    public const byte MinConcurrency = 1;
    public const byte MaxConcurrency = 5;
    public const byte DefaultConcurrency = 3;

    /// <summary>0x70.punchConcurrency 合法化：null（未携带/旧端）或越界 → 缺省 3；1~5 原样采纳。</summary>
    public static byte Normalize(byte? requested)
        => requested is >= MinConcurrency and <= MaxConcurrency ? requested.Value : DefaultConcurrency;

    /// <summary>TCP 齐射同步倒计时 Δ（02 §5.2⑤ 同锚点倒计时，双端共享常量——AI-11 单一事实来源）：
    /// A 以 0x70 延后 Ack 到达为锚、B 以同刻下发的 0x77 PunchFire 到达为锚，各自倒数 Δ 后齐射，
    /// 开火时刻差≈两条控制消息的投递时差。Δ 须大于该时差（数百毫秒量级余量）且远小于打洞窗。</summary>
    public static readonly TimeSpan TcpVolleyCountdown = TimeSpan.FromMilliseconds(400);
}
