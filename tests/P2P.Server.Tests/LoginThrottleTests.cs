using Microsoft.Extensions.Time.Testing;
using P2P.Server.Services;
using Xunit;

namespace P2P.Server.Tests;

/// <summary>
/// M5-04 LoginThrottle 单测（SEC-63、07 §11）：阶梯算术/滑窗衰减/双维独立复位/参数热更——
/// 纯计数组件不睡眠（FakeTimeProvider 只驱动窗算术；延迟执行与阶跃审计在入口集成测）。
/// </summary>
public sealed class LoginThrottleTests
{
    private readonly FakeTimeProvider _time = new(DateTimeOffset.UtcNow);

    [Fact]
    public void 阶梯_指数递增_封顶后不增长且阶跃仅前五档()
    {
        var t = new LoginThrottle(new LoginThrottleOptions(), _time);
        var expected = new[] { 500, 1000, 2000, 4000, 8000, 8000, 8000 }; // min(500×2^(f−1), 8000)
        for (var i = 0; i < expected.Length; i++)
        {
            var r = t.RecordFailure(LoginThrottle.DimAccount, "u");
            Assert.Equal(expected[i], r.DelayMs);
            Assert.Equal(i + 1, r.Fails);
            if (i < 5) Assert.True(r.SteppedUp, $"fails={i + 1} 应为跨档首次");
            else Assert.False(r.SteppedUp, $"fails={i + 1} 达帽后同档不应阶跃");
        }
        // 达帽后同档不再阶跃（≤每窗 5 条/键，07 §11.3）
        Assert.False(t.RecordFailure(LoginThrottle.DimAccount, "u").SteppedUp);
        Assert.Equal(8000, t.LoginDelayMs("u", null));
    }

    [Fact]
    public void 滑窗衰减_推进超窗计数归零()
    {
        var t = new LoginThrottle(new LoginThrottleOptions(), _time);
        t.RecordFailure(LoginThrottle.DimIp, "1.2.3.4");       // t0
        _time.Advance(TimeSpan.FromSeconds(300));
        t.RecordFailure(LoginThrottle.DimIp, "1.2.3.4");       // t0+300s
        _time.Advance(TimeSpan.FromSeconds(300));
        t.RecordFailure(LoginThrottle.DimIp, "1.2.3.4");       // t0+600s
        Assert.Equal(2000, t.LoginDelayMs(null, "1.2.3.4"));

        _time.Advance(TimeSpan.FromSeconds(600)); // 至 t0+1200s：t0/t0+300 出窗，仅 t0+600 在（age 600 < 900）
        Assert.Equal(500, t.LoginDelayMs(null, "1.2.3.4"));
        _time.Advance(TimeSpan.FromSeconds(901)); // 全部出窗 → 归零，重新从 1 计
        Assert.Equal(0, t.LoginDelayMs(null, "1.2.3.4"));
        Assert.Equal(1, t.RecordFailure(LoginThrottle.DimIp, "1.2.3.4").Fails);
    }

    [Fact]
    public void 账户维复位独立于IP维_取大者合成()
    {
        var t = new LoginThrottle(new LoginThrottleOptions(), _time);
        for (var i = 0; i < 3; i++) t.RecordFailure(LoginThrottle.DimAccount, "u");
        t.RecordFailure(LoginThrottle.DimIp, "9.9.9.9");
        Assert.Equal(2000, t.LoginDelayMs("u", "9.9.9.9")); // 双维取大（2000 vs 500）

        t.Reset(LoginThrottle.DimAccount, "u"); // 成功复位仅账户维
        Assert.Equal(0, t.LoginDelayMs("u", null));
        Assert.Equal(500, t.LoginDelayMs("u", "9.9.9.9")); // IP 维仍在
        t.Reset(LoginThrottle.DimIp, "9.9.9.9");
        Assert.Equal(0, t.LoginDelayMs("u", "9.9.9.9"));
    }

    [Fact]
    public void 参数热更_窗与帽即时生效()
    {
        var t = new LoginThrottle(new LoginThrottleOptions(), _time);
        t.RecordFailure(LoginThrottle.DimAccount, "u");
        t.RecordFailure(LoginThrottle.DimAccount, "u");
        Assert.Equal(1000, t.LoginDelayMs("u", null));

        t.Update(windowSec: 60, delayCapMs: 500); // AdminSystemApi PUT 联动（07 §11 运行期热更）
        Assert.Equal(500, t.LoginDelayMs("u", null)); // 帽收紧立即钳制
        _time.Advance(TimeSpan.FromSeconds(61)); // 新窗 60s：已出窗
        Assert.Equal(0, t.LoginDelayMs("u", null));
        Assert.Equal(500, t.RecordFailure(LoginThrottle.DimAccount, "u").DelayMs);
        Assert.False(t.RecordFailure(LoginThrottle.DimAccount, "u").SteppedUp); // 帽=首档：第 2 次不跨档
    }

    [Fact]
    public void IP维窗口快照_仅IP维_降序_出窗归零()
    {
        var t = new LoginThrottle(new LoginThrottleOptions(), _time);
        t.RecordFailure(LoginThrottle.DimAccount, "u");
        t.RecordFailure(LoginThrottle.DimAccount, "u"); // account 维 2 次（不入快照）
        t.RecordFailure(LoginThrottle.DimIp, "203.0.113.7");
        t.RecordFailure(LoginThrottle.DimIp, "203.0.113.7");
        t.RecordFailure(LoginThrottle.DimIp, "198.51.100.9");

        var snap = t.SnapshotIpWindow(900); // M5-07 AlertPusher 聚合消费面
        Assert.Equal(2, snap.Count);
        Assert.Equal(("203.0.113.7", 2), (snap[0].Ip, snap[0].Count)); // 计数降序
        Assert.Equal(("198.51.100.9", 1), (snap[1].Ip, snap[1].Count));
        Assert.Equal(3, snap.Sum(s => s.Count)); // 总数=四入口 IP 维聚合

        _time.Advance(TimeSpan.FromSeconds(901)); // 全部出窗 → 空快照（告警基线随窗衰减）
        Assert.Empty(t.SnapshotIpWindow(900));
    }
}
