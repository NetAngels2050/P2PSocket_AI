// M5-07/08/09 安全中心端点组（SEC-71/72/73、07 §13.1~§13.4、04 §3.2）：
// POST /api/security/alert-test（M5-07）——立即向已配置 webhook 发 type=test 载荷（管理页
// 「测试推送」按钮载体）；与 alert_enabled 开关独立（显式手动动作，单次尝试即时反馈）；
// 须先配 alert_webhook_url（空 → 400 {1001}）。
// M5-08：POST/DELETE /api/security/blacklist——IP 手动加黑 {ip, reason?}（manual 永久条目）/解封；
// 处置审计 ip_block{ip,reason}/ip_unblock{ip}（07 §13.3 命中不逐条、处置入审计——OQ-22①）。
// M5-09：GET /api/security/overview 安全中心聚合（07 §13.2——今日/近 7 天计数血缘=audit_logs
// 时间窗查询+StunGuard 三分桶自启动累计+黑名单快照与 autoban/注册开关现值）；
// POST /api/security/lockdown 踢全部会话（07 §13.4——断开全部 ControlSession
// reason=security_lockdown+审计；不设拒连窗）。
using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using P2P.Server.Data;
using P2P.Server.Services;

namespace P2P.Server.Web;

public sealed class SecurityApi(
    IDbContextFactory<AppDbContext> dbFactory,
    TimeProvider? time = null,
    AuditLogger? audit = null,
    BlacklistStore? blacklist = null,
    AlertPusher? alert = null,
    StunService? stun = null,
    ControlServer? control = null)
{
    private static readonly string[] LoginFailEvents = ["login_failed", "admin_login_fail"];
    private static readonly string[] RegisterEvents = ["register", "register_recover"];
    private static readonly string[] DenyEvents =
        ["punch_deny", "mapping_deny", "passive_deny", "group_join_deny"];

    private readonly TimeProvider _time = time ?? TimeProvider.System;

    public void Map(WebApplication app)
    {
        // 安全中心聚合（M5-09，07 §13.2）：可选件缺失时相关节呈零值/空快照（裸 API 形态先例）
        app.MapGet("/api/security/overview", async ctx =>
        {
            var now = _time.GetLocalNow().UtcDateTime;
            var todayFloor = now.Date;            // 今日=UTC 日界（AuditLogger 写入即 UTC，同源口径）
            var weekFloor = now.AddDays(-7);      // 近 7 天=滚动 168h
            string[] events = [.. LoginFailEvents, .. RegisterEvents, .. DenyEvents];
            List<AuditLog> rows;
            await using (var db = await dbFactory.CreateDbContextAsync(ctx.RequestAborted))
                rows = await db.AuditLogs.AsNoTracking()
                    .Where(a => a.Ts >= weekFloor && events.Contains(a.Event))
                    .Select(a => new AuditLog { Ts = a.Ts, Event = a.Event })
                    .ToListAsync(ctx.RequestAborted);

            int Count(IEnumerable<string> ev, DateTime floor) =>
                rows.Count(r => r.Ts >= floor && ev.Contains(r.Event));

            var cfg = await ReadConfigAsync(ctx.RequestAborted);
            var metrics = stun?.Guard.Metrics(); // 三分桶自启动累计（uptime 反推启动时刻）
            await WriteDataAsync(ctx, new SecurityOverviewView(
                Today: new SecurityCountView(
                    Count(LoginFailEvents, todayFloor), Count(RegisterEvents, todayFloor),
                    Count(DenyEvents, todayFloor)),
                Week: new SecurityCountView(
                    Count(LoginFailEvents, weekFloor), Count(RegisterEvents, weekFloor),
                    Count(DenyEvents, weekFloor)),
                Stun: new SecurityStunView(metrics?.Rate ?? 0, metrics?.Auth ?? 0,
                    metrics?.Circuit ?? 0,
                    metrics is null ? null : now.AddSeconds(-metrics.UptimeSec)),
                Blacklist: blacklist?.Snapshot() ?? [],
                Hits: blacklist?.HitSnapshot().ToDictionary(kv => kv.Key, kv => kv.Value) ?? [],
                Autoban: new AutobanRuleView(
                    cfg["autoban_enabled"] == "1", int.Parse(cfg["autoban_window_sec"]),
                    int.Parse(cfg["autoban_fail_count"]), int.Parse(cfg["autoban_duration_sec"])),
                RegistrationOpen: cfg["device_registration_open"] == "1"));
        });

        // 踢全部会话（M5-09，07 §13.4 定案）：断开全部在线 ControlSession+审计；不设拒连窗
        // （设备凭 deviceSecret 立即重连——长效封锁走 IP 黑名单，两者互补）
        app.MapPost("/api/security/lockdown", async ctx =>
        {
            var sessions = control?.Sessions ?? [];
            foreach (var s in sessions)
                await s.CloseAsync("security_lockdown");
            await (audit?.WriteAsync("security_lockdown",
                detail: new { kicked = sessions.Count }, ct: ctx.RequestAborted) ?? Task.CompletedTask);
            await WriteDataAsync(ctx, new LockdownResultView(sessions.Count));
        });

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

    private async Task<Dictionary<string, string>> ReadConfigAsync(CancellationToken ct)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var cfg = new ServerConfigStore(db);
        return new Dictionary<string, string>
        {
            ["autoban_enabled"] = cfg.Get("autoban_enabled"),
            ["autoban_window_sec"] = cfg.Get("autoban_window_sec"),
            ["autoban_fail_count"] = cfg.Get("autoban_fail_count"),
            ["autoban_duration_sec"] = cfg.Get("autoban_duration_sec"),
            ["device_registration_open"] = cfg.Get("device_registration_open"),
        };
    }

    private static async Task WriteDataAsync(HttpContext ctx, object data)
    {
        ctx.Response.StatusCode = StatusCodes.Status200OK;
        await ctx.Response.WriteAsJsonAsync(new { code = 0, msg = "ok", data });
    }

    private static async Task WriteAsync(HttpContext ctx, int status, int code, string message)
    {
        ctx.Response.StatusCode = status;
        await ctx.Response.WriteAsJsonAsync(new { code, message });
    }
}
