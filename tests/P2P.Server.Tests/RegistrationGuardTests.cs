using System.Net;
using Microsoft.Extensions.Time.Testing;
using P2P.Server.Services;
using Xunit;

namespace P2P.Server.Tests;

/// <summary>
/// M5-02 注册准入闸② 单 IP 令牌桶（SEC-61、07 §5.1）：容量=速率初始满桶、小时推进补币封顶、
/// 键空间按 IP 独立。
/// </summary>
public sealed class RegistrationGuardTests
{
    private static readonly IPAddress IpA = IPAddress.Parse("203.0.113.10");
    private static readonly IPAddress IpB = IPAddress.Parse("203.0.113.11");

    [Fact]
    public void 初始满桶_容量内放行超容拒()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var guard = new RegistrationGuard(new RegistrationGuardOptions { PerHour = 3 }, time);

        Assert.True(guard.TryAcquire(IpA));
        Assert.True(guard.TryAcquire(IpA));
        Assert.True(guard.TryAcquire(IpA)); // 容量 3 初始即满
        Assert.False(guard.TryAcquire(IpA)); // 第 4 次拒（10/h 语义的缩样）
    }

    [Fact]
    public void 小时推进_按速率补币且封顶容量()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var guard = new RegistrationGuard(new RegistrationGuardOptions { PerHour = 3 }, time);
        for (var i = 0; i < 3; i++) guard.TryAcquire(IpA); // 耗尽

        time.Advance(TimeSpan.FromMinutes(30)); // 补 1.5 枚
        Assert.True(guard.TryAcquire(IpA));  // 余 0.5
        Assert.False(guard.TryAcquire(IpA));

        time.Advance(TimeSpan.FromHours(2));  // 0.5+6 → 封顶容量 3
        Assert.True(guard.TryAcquire(IpA));
        Assert.True(guard.TryAcquire(IpA));
        Assert.True(guard.TryAcquire(IpA));
        Assert.False(guard.TryAcquire(IpA)); // 封顶证明：不累积到 6
    }

    [Fact]
    public void 不同IP_桶独立()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var guard = new RegistrationGuard(new RegistrationGuardOptions { PerHour = 1 }, time);

        Assert.True(guard.TryAcquire(IpA));
        Assert.False(guard.TryAcquire(IpA)); // A 耗尽
        Assert.True(guard.TryAcquire(IpB));  // B 独立满桶
    }
}
