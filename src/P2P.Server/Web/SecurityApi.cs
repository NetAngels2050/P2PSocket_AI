// M5-07/08 安全中心端点组（SEC-71/73、07 §13.1/§13.3、04 §3.2）：
// POST /api/security/alert-test（M5-07）——立即向已配置 webhook 发 type=test 载荷（管理页
// 「测试推送」按钮载体）；与 alert_enabled 开关独立（显式手动动作，单次尝试即时反馈）；
// 须先配 alert_webhook_url（空 → 400 {1001}）。
// M5-08：POST/DELETE /api/security/blacklist——IP 手动加黑 {ip, reason?}（manual 永久条目）/解封；
// 处置审计 ip_block{ip,reason}/ip_unblock{ip}（07 §13.3 命中不逐条、处置入审计——OQ-22①）。
// M5-09 overview/lockdown 随任务挂载本组。
using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using P2P.Server.Data;
using P2P.Server.Services;

namespace P2P.Server.Web;

public sealed class SecurityApi(
    IDbContextFactory<AppDbContext> dbFactory,
    AuditLogger? audit = null,
    BlacklistStore? blacklist = null,
    AlertPusher? alert = null)
{
    public void Map(WebApplication app)
    {
        if (blacklist is not null)
        {
            // 手动加黑：manual 永久（同 IP auto 条目升级覆盖——BlacklistStore 语义）+审计 ip_block
            app.MapPost("/api/security/blacklist", async ctx =>
            {
                var req = await ctx.Request.ReadFromJsonAsync<BlockRequest>(ctx.RequestAborted);
                if (req is null || !IPAddress.TryParse(req.Ip, out _))
                {
                    await WriteAsync(ctx, StatusCodes.Status400BadRequest, 1001, "参数错误（ip 须为合法地址）");
                    return;
                }
                var entry = await blacklist.BlockManualAsync(req.Ip, req.Reason, ctx.RequestAborted);
                await (audit?.WriteAsync("ip_block", detail: new { ip = entry.Ip, reason = entry.Reason },
                    ct: ctx.RequestAborted) ?? Task.CompletedTask);
                await WriteAsync(ctx, StatusCodes.Status200OK, 0, "ok");
            });

            // 解封：manual/auto 皆删行（auto 提前解封=管理员显式动作）+审计 ip_unblock
            app.MapDelete("/api/security/blacklist/{ip}", async (string ip, HttpContext ctx) =>
            {
                if (!await blacklist.RemoveAsync(ip, ctx.RequestAborted))
                {
                    await WriteAsync(ctx, StatusCodes.Status404NotFound, 1002, "条目不存在");
                    return;
                }
                await (audit?.WriteAsync("ip_unblock", detail: new { ip }, ct: ctx.RequestAborted)
                    ?? Task.CompletedTask);
                await WriteAsync(ctx, StatusCodes.Status200OK, 0, "ok");
            });
        }

        if (alert is null) return;
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

    private sealed record BlockRequest(string Ip, string? Reason);

    private static async Task WriteAsync(HttpContext ctx, int status, int code, string message)
    {
        ctx.Response.StatusCode = status;
        await ctx.Response.WriteAsJsonAsync(new { code, message });
    }
}
