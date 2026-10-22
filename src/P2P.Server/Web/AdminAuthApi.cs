// M3-02 管理员会话与账号（FR-S-203 收口、04 §3.1、07 §8、OQ-3/D16、AI-17）：
// login（admin/admin 默认；mustChangePassword=仍是默认口令即 true——提示不强制阻断）/
// change-password（独立于 0x23 的 Web 载体实现：admin 行直接改库+审计）/
// logout（会话即删）。登录成功/失败审计 admin_login/admin_login_fail。
// M5-04 防爆破并入统一 LoginThrottle（SEC-63、07 §11.1）：既有独立 per-IP 阶梯退役——
// admin 单账户=账户维退化常量（真实账户名，防伪造用户名分片计数）+IP 维与 0x21 共享同键
// （任一入口失败抬高该 IP 全部入口延迟）；封顶随 login_delay_cap_ms 不再各持一套；
// 成功复位仅账户维（原 per-IP 成功复位语义退役——IP 维滑窗自然衰减，07 §11.1）。
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using P2P.Core.Crypto;
using P2P.Server.Data;
using P2P.Server.Services;

namespace P2P.Server.Web;

/// <summary>管理端认证端点组（挂在 ServerWebHost 装配的 WebApplication 上）。</summary>
public sealed class AdminAuthApi(
    IDbContextFactory<AppDbContext> dbFactory,
    AuditLogger audit,
    LoginThrottle? throttle = null,
    TimeProvider? time = null)
{
    private readonly TimeProvider _time = time ?? TimeProvider.System;

    public void Map(WebApplication app, AdminSessionStore sessions)
    {
        app.MapPost("/api/auth/login", async ctx =>
        {
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            LoginRequest? req;
            try { req = await ctx.Request.ReadFromJsonAsync<LoginRequest>(ctx.RequestAborted); }
            catch (JsonException) { req = null; }
            if (req is null || string.IsNullOrEmpty(req.Username) || string.IsNullOrEmpty(req.Password))
            {
                await WriteAsync(ctx, StatusCodes.Status400BadRequest, 1001, "参数错误");
                return;
            }

            // 限速先于校验（爆破者无法跳过）；双维取大——admin 常量账户维+IP 维（07 §11.1）
            await WaitThrottleAsync(throttle?.LoginDelayMs(DbInitializer.AdminUsername, ip), ctx.RequestAborted);

            await using var db = await dbFactory.CreateDbContextAsync(ctx.RequestAborted);
            var admin = await db.Users.SingleOrDefaultAsync(
                u => u.Username == DbInitializer.AdminUsername && u.IsAdmin, ctx.RequestAborted);
            if (admin is null || !PasswordHasher.Verify(req.Password, admin.PasswordHash))
            {
                await audit.WriteAsync("admin_login_fail", userId: admin?.Id,
                    detail: new { ip, username = req.Username }, ct: ctx.RequestAborted); // AI-17：无凭据材料
                if (throttle is not null)
                {
                    await RecordThrottleFailAsync(admin?.Id, LoginThrottle.DimAccount,
                        DbInitializer.AdminUsername, ctx.RequestAborted);
                    await RecordThrottleFailAsync(admin?.Id, LoginThrottle.DimIp, ip, ctx.RequestAborted);
                }
                await WriteAsync(ctx, StatusCodes.Status401Unauthorized, 2001, "用户名或密码错误");
                return;
            }

            throttle?.Reset(LoginThrottle.DimAccount, DbInitializer.AdminUsername); // 账户维成功复位（IP 维不清零）
            var sessionId = sessions.Create();
            ctx.Response.Cookies.Append(AdminSessionStore.CookieName, sessionId, new CookieOptions
            {
                HttpOnly = true,
                SameSite = SameSiteMode.Strict,
                Secure = false, // HTTP（D11 仅本机监听）
                Path = "/",
            });
            await audit.WriteAsync("admin_login", userId: admin.Id,
                detail: new { ip }, ct: ctx.RequestAborted);
            // 首登判定（编制小口径）：仍是默认口令即提示改密（不阻断）
            var mustChange = PasswordHasher.Verify(DbInitializer.AdminUsername, admin.PasswordHash);
            await WriteAsync(ctx, StatusCodes.Status200OK, 0, "ok", new LoginResult(mustChange));
        });

        app.MapPost("/api/auth/change-password", async ctx =>
        {
            ChangePasswordRequest? req;
            try { req = await ctx.Request.ReadFromJsonAsync<ChangePasswordRequest>(ctx.RequestAborted); }
            catch (JsonException) { req = null; }
            if (req is null || string.IsNullOrEmpty(req.OldPassword) || string.IsNullOrEmpty(req.NewPassword))
            {
                await WriteAsync(ctx, StatusCodes.Status400BadRequest, 1001, "参数错误");
                return;
            }
            if (req.NewPassword.Length < 6) // 与 0x23 同口径（04 §2.3）
            {
                await WriteAsync(ctx, StatusCodes.Status400BadRequest, 1001, "新密码长度至少 6 位");
                return;
            }

            await using var db = await dbFactory.CreateDbContextAsync(ctx.RequestAborted);
            var admin = await db.Users.SingleOrDefaultAsync(
                u => u.Username == DbInitializer.AdminUsername && u.IsAdmin, ctx.RequestAborted);
            if (admin is null || !PasswordHasher.Verify(req.OldPassword, admin.PasswordHash))
            {
                await WriteAsync(ctx, StatusCodes.Status401Unauthorized, 2001, "当前密码不正确");
                return;
            }

            admin.PasswordHash = PasswordHasher.Hash(req.NewPassword);
            admin.UpdatedAt = DateTime.UtcNow;
            await db.SaveChangesAsync(ctx.RequestAborted);
            await audit.WriteAsync("admin_change_password", userId: admin.Id, ct: ctx.RequestAborted);
            await WriteAsync(ctx, StatusCodes.Status200OK, 0, "ok");
        });

        app.MapPost("/api/auth/logout", async ctx =>
        {
            if (ctx.Request.Cookies.TryGetValue(AdminSessionStore.CookieName, out var sid))
                sessions.Remove(sid);
            ctx.Response.Cookies.Delete(AdminSessionStore.CookieName, new CookieOptions
            {
                HttpOnly = true,
                SameSite = SameSiteMode.Strict,
                Path = "/",
            });
            await WriteAsync(ctx, StatusCodes.Status200OK, 0, "ok");
        });
    }

    private static async Task WriteAsync(HttpContext ctx, int status, int code, string message, object? data = null)
    {
        ctx.Response.StatusCode = status;
        await ctx.Response.WriteAsJsonAsync(new { code, message, data });
    }

    /// <summary>阶梯延迟（TimeProvider 版——FakeTimeProvider 夹具推进假时钟即放行；07 §11.1 先于凭据校验）。</summary>
    private async Task WaitThrottleAsync(int? delayMs, CancellationToken ct)
    {
        if (delayMs is > 0)
            await Task.Delay(TimeSpan.FromMilliseconds(delayMs.Value), _time, ct);
    }

    /// <summary>记一维失败+阶跃审计（07 §11.3：延迟值跨档才记；admin 路径无 device——仅 userId 维度可选）。</summary>
    private async Task RecordThrottleFailAsync(Guid? userId, string dim, string key, CancellationToken ct)
    {
        var r = throttle!.RecordFailure(dim, key);
        if (!r.SteppedUp) return;
        object detail = dim == LoginThrottle.DimAccount
            ? new { dim, account = key, fails = r.Fails, delayMs = r.DelayMs }
            : new { dim, ip = key, fails = r.Fails, delayMs = r.DelayMs };
        await audit.WriteAsync("login_throttled", userId: userId, detail: detail, ct: ct);
    }

    private sealed record LoginRequest(string Username, string Password);

    private sealed record ChangePasswordRequest(string OldPassword, string NewPassword);
}
