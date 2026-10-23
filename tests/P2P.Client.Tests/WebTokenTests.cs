// M5-12/SEC-82 WebToken 单测（07 §14.2 验收：无 token 拒/有 token 过属集成面）：
// 生成=32B CSPRNG 64hex 小写；ACL 文件写穿（web-token）；同目录再生成即轮换
//（每次新值 + 文件覆盖——随服务重启旧值失效的存储面证明）。
using P2P.Client.Storage;
using P2P.Client.Web;
using Xunit;

namespace P2P.Client.Tests;

public sealed class WebTokenTests
{
    private static string TempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"p2p-webtoken-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static string TokenPath(string dir) => Path.Combine(dir, ClientPaths.WebTokenFileName);

    [Fact]
    public void 生成_64hex小写_落盘内容一致()
    {
        var dir = TempDir();
        var token = new WebToken(dir);
        Assert.Matches("^[0-9a-f]{64}$", token.Value); // 32B → 64 位 hex 小写
        Assert.Equal(token.Value, File.ReadAllText(TokenPath(dir)).Trim());
    }

    [Fact]
    public void 再生成即轮换_文件覆盖为现值()
    {
        var dir = TempDir();
        var first = new WebToken(dir).Value;
        var second = new WebToken(dir).Value;
        Assert.NotEqual(first, second); // CSPRNG 随机（64hex 空间碰撞概率可忽略）
        Assert.Equal(second, File.ReadAllText(TokenPath(dir)).Trim()); // 写穿覆盖=重启轮换后旧值不残留
    }
}
