// M5-07 安全中心端点组首件（SEC-71、07 §13.1、04 §3.2）：POST /api/security/alert-test——
// 立即向已配置 webhook 发 type=test 载荷（管理页「测试推送」按钮载体，手动验证通路）。
// 与 alert_enabled 开关独立（显式手动动作，单次尝试即时反馈）；须先配 alert_webhook_url
// （空 → 400 {1001}）。M5-09 overview/blacklist/lockdown 随任务挂载本组。
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using P2P.Server.Data;
using P2P.Server.Services;

namespace P2P.Server.Web;

public sealed class SecurityApi(IDbContextFactory<AppDbContext> dbFactory, AlertPusher alert)
{
    public void Map(WebApplication app)
    {
        app.MapPost("/api/security/alert-test", async ctx =>
        {
            string url;
            await using (var db = await dbFactory.CreateDbContextAsync(ctx.RequestAborted))
                url = new ServerConfigStore(db).Get("alert_webhook_url");
            if (url.Length == 0)
            {
                await WriteAsync(ctx, StatusCodes.Status400BadRequest, 1001,
                    "参数错误（须先配置 alert_webhook_url）");
                return;
            }
            if (!await alert.TriggerTestAsync(url, ctx.RequestAborted))
            {
                // 5003 复用（5004 v1.67 复用同法）：接收端不可达——HTTP 502 携带 SERVER_UNREACHABLE
                await WriteAsync(ctx, StatusCodes.Status502BadGateway, 5003,
                    "测试推送失败（接收端未响应，详见服务端日志）");
                return;
            }
            await WriteAsync(ctx, StatusCodes.Status200OK, 0, "ok");
        });
    }

    private static async Task WriteAsync(HttpContext ctx, int status, int code, string message)
    {
        ctx.Response.StatusCode = status;
        await ctx.Response.WriteAsJsonAsync(new { code, message });
    }
}
