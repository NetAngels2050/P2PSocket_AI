// M5-12/SEC-82 本地 Web 请求鉴权（07 §14.2、FR-C-813）：每次服务启动生成 32B CSPRNG
// token（64 位 hex 小写，重启即轮换旧值失效），仅内存持有 + 落 ACL 文件写穿
//（Windows=%ProgramData%\P2PClient 沿数据目录 ACL 继承、Linux=/etc/p2p-client 0600
// 显式收紧）。收敛「本机任意进程裸 HTTP 驱使 SYSTEM 服务」代理面（A-18 后半）；
// 不对抗能读 token 文件的同机管理员级攻击者（ACL 即边界，07 §14.2）。
using System.Security.Cryptography;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using P2P.Client.Storage;
using P2P.Core.Protocol;

namespace P2P.Client.Web;

/// <summary>启动期本地 Web token（生成 + ACL 文件写穿；宿主持有并注入鉴权中间件）。</summary>
public sealed class WebToken
{
    public string Value { get; }

    public WebToken(string baseDir)
    {
        Value = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        var path = Path.Combine(baseDir, ClientPaths.WebTokenFileName);
        if (OperatingSystem.IsLinux())
        {
            // 0600（07 §14.2）：仅属主读写；FileMode.Create 截断覆盖=轮换写穿
            //（UnixCreateMode 仅建新文件时生效，既有文件保留原权限）
            using var fs = new FileStream(path, new FileStreamOptions
            {
                Mode = FileMode.Create,
                Access = FileAccess.Write,
                Share = FileShare.None,
                UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
            });
            using var w = new StreamWriter(fs);
            w.Write(Value);
        }
        else
        {
            // Windows 沿数据目录 ACL 继承（07 §4 数据目录收紧），不另设文件级 ACL
            File.WriteAllText(path, Value);
        }
    }
}

/// <summary>本地 Web 请求鉴权中间件（07 §14.2）：/api/* 与 /ws/status 全量校验、静态资源
/// 豁免（SPA 产物非机密，保护面=API/WS）。载体：REST=Authorization: Bearer；WS 升级=query
/// token（浏览器 WebSocket API 无法自定义头——07 §14.2 定案；头载体对非浏览器客户端同收）。
/// 未携带/错误：401 + envelope{2001}（04 §5 既有码，与登录失效同口径）。</summary>
public static class WebTokenAuthExtensions
{
    public static IApplicationBuilder UseWebTokenAuth(this IApplicationBuilder app, string token)
    {
        app.Use(async (ctx, next) =>
        {
            var path = ctx.Request.Path;
            if (!path.StartsWithSegments("/api") && path != "/ws/status") { await next(); return; }
            if (ctx.Request.Headers.Authorization.ToString() != $"Bearer {token}"
                && !(path == "/ws/status" && ctx.Request.Query["token"].ToString() == token))
            {
                ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await ctx.Response.WriteAsJsonAsync(
                    new { code = ErrorCode.Unauthorized, msg = "未登录或凭据失效", data = (object?)null },
                    Api.Json);
                return;
            }
            await next();
        });
        return app;
    }
}
