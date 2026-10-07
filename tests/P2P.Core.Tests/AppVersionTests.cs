using P2P.Core;
using Xunit;

namespace P2P.Core.Tests;

/// <summary>
/// M4-01 版本注入（08 §1）：src/Directory.Build.props 统一 Version=1.0.0 + git 短哈希/
/// 构建时间写入 ThisAssembly.Metadata（GitCommit/BuildDate）。测试程序集引用 P2P.Core
/// 的编译产物即携带注入值；git 不可用的源码包构建容错为 unknown（值恒非空不阻断展示）。
/// </summary>
public sealed class AppVersionTests
{
    [Fact]
    public void 版本_三段式语义版本()
    {
        Assert.Matches(@"^\d+\.\d+\.\d+$", AppVersion.Version);
        Assert.Equal("1.0.0", AppVersion.Version); // M4 清单编制定案：首个完整交付版本
    }

    [Fact]
    public void 提交哈希_非空_七位十六进制或容错值()
    {
        Assert.False(string.IsNullOrWhiteSpace(AppVersion.Commit));
        Assert.Matches(@"^([0-9a-f]{7,12}|unknown)$", AppVersion.Commit);
    }

    [Fact]
    public void 构建时间_非空()
    {
        Assert.False(string.IsNullOrWhiteSpace(AppVersion.BuildDate));
    }

    [Fact]
    public void 只读快照_进程内恒定()
    {
        Assert.Equal(AppVersion.Version, AppVersion.Version);
        Assert.Equal(AppVersion.Commit, AppVersion.Commit);
    }
}
