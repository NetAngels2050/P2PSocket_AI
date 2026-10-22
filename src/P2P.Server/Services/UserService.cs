using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using P2P.Core.Crypto;
using P2P.Core.Protocol;
using P2P.Server.Data;

namespace P2P.Server.Services;

/// <summary>
/// 用户与能力模式处理（02 §2.4 0x20/0x21/0x22/0x23/0x13；FR-S-201/202/205/106/107）：
/// 注册受 registration_open 开关控制；登录绑定设备 owner 并切 normal；
/// 登出切 passive（能力模式为会话态，05 §8）+ 本人映射 0x75(logged_out) 失效（M2-12，PRD 05 §4 L1 失效）；
/// 改密（M2-27）：旧密码校验 → 覆写 hash（不裁会话——能力模式不变，05 §3）。
/// 改名（v1.58，FR-S-107）：trim 后 1~64（与客户端 04 §2.1 口径一致，防协议直连绕过）→
/// 改库 + 审计 device_rename + 0x41 推送（Ack 先于推送，M2-10 纪律）。
/// M5-04 登录防爆破（SEC-63、07 §11）：0x21/0x23 凭据失败计入 LoginThrottle 双维
/// （account=username+IP 四入口共享），延迟先于凭据校验（正确登录同吃当前档，A-15）、
/// 限流触发=延迟后正常失败应答不设专用错误码（零信息泄漏）；成功复位仅账户维（IP 维滑窗自然衰减）；
/// 阶跃审计 login_throttled（≤每窗 5 条/键）。throttle 可空注入——未装配跳过（测试夹具）。
/// </summary>
public sealed class UserService(
    IDbContextFactory<AppDbContext> dbFactory,
    AuditLogger audit,
    TimeProvider? time = null,
    InvalidationPusher? invalidation = null,
    DeviceListPusher? listPusher = null,
    LoginThrottle? throttle = null)
{
    private readonly TimeProvider _time = time ?? TimeProvider.System;

    /// <summary>0x20 用户注册：registration_open=0 → 2004；用户名占用 → Ack Ok=false。
    /// M5-06/SEC-26：密码经 PasswordBox（ECIES）；缺失/明文非空 → 5004 硬切（07 §10.3，无明文双轨）。</summary>
    public async Task HandleUserRegisterAsync(ControlSession session, UserRegister msg)
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        if (!new ServerConfigStore(db).GetBool("registration_open"))
        {
            await session.SendErrorAsync(ErrorCode.RegistrationClosed, "registration_closed");
            return;
        }
        if (UnboxLoginPassword(session, msg.PasswordBox, msg.Password, out var password) == UnboxOutcome.HardCut)
        {
            await session.SendErrorAsync(ErrorCode.VersionNotSupported, "password_ecies_required");
            return;
        }
        if (string.IsNullOrWhiteSpace(msg.Username) || password.Length < 6)
        {
            await session.SendAsync(new UserRegisterAck(session.NextSeq(), session.ServerTimestamp(),
                MsgType.UserRegister, false));
            return;
        }
        if (await db.Users.AsNoTracking().AnyAsync(u => u.Username == msg.Username))
        {
            await session.SendAsync(new UserRegisterAck(session.NextSeq(), session.ServerTimestamp(),
                MsgType.UserRegister, false));
            return;
        }

        var now = _time.GetLocalNow().UtcDateTime;
        db.Users.Add(new User
        {
            Id = Guid.NewGuid(),
            Username = msg.Username,
            PasswordHash = PasswordHasher.Hash(password),
            CreatedAt = now,
            UpdatedAt = now,
        });
        await db.SaveChangesAsync();
        await session.SendAsync(new UserRegisterAck(session.NextSeq(), session.ServerTimestamp(),
            MsgType.UserRegister, true));
    }

    /// <summary>0x21 登录：凭据校验 → 设备 owner 绑定 + 能力切 normal + token（FR-S-106）。
    /// 防爆破（M5-04/07 §11）：双维延迟先于校验；失败计双维+阶跃审计；成功复位仅账户维。
    /// M5-06/SEC-26：密码经 PasswordBox；缺失/明文非空 → 5004 硬切（先于延迟——格式闸不构成凭据 oracle）；
    /// 解密失败并入凭据失败口径（不泄漏原因，07 §10.3）。</summary>
    public async Task HandleLoginAsync(ControlSession session, UserLogin msg)
    {
        var unbox = UnboxLoginPassword(session, msg.PasswordBox, msg.Password, out var password);
        if (unbox == UnboxOutcome.HardCut)
        {
            await session.SendErrorAsync(ErrorCode.VersionNotSupported, "password_ecies_required");
            return;
        }
        await using var db = await dbFactory.CreateDbContextAsync();
        var ip = session.RemoteEndPoint?.Address.ToString();
        await WaitThrottleAsync(throttle?.LoginDelayMs(msg.Username, ip)); // 先于凭据校验（A-15 含正确登录）

        var user = await db.Users.AsNoTracking()
            .SingleOrDefaultAsync(u => u.Username == msg.Username);
        var ok = unbox == UnboxOutcome.Ok && user is not null && !user.Disabled
            && PasswordHasher.Verify(password, user.PasswordHash);
        if (!ok)
        {
            await audit.WriteAsync("login_failed", session.DeviceId, detail: new { msg.Username });
            if (throttle is not null)
            {
                await RecordThrottleFailAsync(session.DeviceId, LoginThrottle.DimAccount, msg.Username);
                if (ip is not null) await RecordThrottleFailAsync(session.DeviceId, LoginThrottle.DimIp, ip);
            }
            await session.SendAsync(new UserLoginAck(session.NextSeq(), session.ServerTimestamp(),
                MsgType.UserLogin, false, CapabilityMode.Passive, ""));
            return;
        }

        throttle?.Reset(LoginThrottle.DimAccount, msg.Username); // 账户维成功复位（IP 维不清零，07 §11.1）
        await db.Devices.Where(d => d.Id == session.DeviceId)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.OwnerUserId, user!.Id));
        session.Capability = CapabilityMode.Normal;
        session.OwnerUserId = user!.Id;

        var token = Convert.ToHexString(RandomGenerator.Bytes(16)).ToLowerInvariant();
        await audit.WriteAsync("login", session.DeviceId, user.Id);
        await session.SendAsync(new UserLoginAck(session.NextSeq(), session.ServerTimestamp(),
            MsgType.UserLogin, true, CapabilityMode.Normal, token));
    }

    /// <summary>0x22 登出：能力切 passive（FR-C-603；owner 绑定保留，下次登录免重绑）。</summary>
    public async Task HandleLogoutAsync(ControlSession session, UserLogout msg)
    {
        session.Capability = CapabilityMode.Passive;
        session.OwnerUserId = null;
        await session.SendAsync(new UserLogoutAck(session.NextSeq(), session.ServerTimestamp(),
            MsgType.UserLogout, true));
        // L1 失效（PRD 05 §4）：本人 enabled 映射全部失效停转发——Ack 先于推送（M2-10 纪律）
        if (invalidation is not null)
            await invalidation.PushOwnedAsync(session.DeviceId, InvalidationReason.LoggedOut);
    }

    /// <summary>0x23 修改自己密码（M2-27，FR-S-205；主动类——passive 拒 2002）：
    /// 旧密码校验失败/未登录 → Ack Ok=false（不泄漏具体原因）；成功覆写 hash 并审计。
    /// 防爆破（M5-04/07 §11）：与 0x21 同双维同键——账户维共享使改密失败同样抬高登录延迟（反之亦然）。
    /// M5-06/SEC-26：旧/新密码分别经 Old/NewPasswordBox；任一缺失或明文非空 → 5004 硬切（07 §10.3）。</summary>
    public async Task HandleChangePasswordAsync(ControlSession session, UserChangePassword msg)
    {
        if (session.OwnerUserId is not { } userId)
        {
            await session.SendErrorAsync(ErrorCode.Unauthorized, "login_required");
            return;
        }
        var oldUnbox = UnboxLoginPassword(session, msg.OldPasswordBox, msg.OldPassword, out var oldPassword);
        var newUnbox = UnboxLoginPassword(session, msg.NewPasswordBox, msg.NewPassword, out var newPassword);
        if (oldUnbox == UnboxOutcome.HardCut || newUnbox == UnboxOutcome.HardCut)
        {
            await session.SendErrorAsync(ErrorCode.VersionNotSupported, "password_ecies_required");
            return;
        }
        await using var db = await dbFactory.CreateDbContextAsync();
        var user = await db.Users.SingleOrDefaultAsync(u => u.Id == userId);
        var ip = session.RemoteEndPoint?.Address.ToString();
        await WaitThrottleAsync(throttle?.LoginDelayMs(user?.Username, ip)); // 先于凭据校验
        if (user is null || user.Disabled
            || oldUnbox == UnboxOutcome.Corrupt || newUnbox == UnboxOutcome.Corrupt
            || string.IsNullOrEmpty(oldPassword)
            || newPassword.Length < 6
            || !PasswordHasher.Verify(oldPassword, user.PasswordHash))
        {
            await audit.WriteAsync("password_change_failed", session.DeviceId, userId: userId);
            if (throttle is not null && user is not null)
            {
                await RecordThrottleFailAsync(session.DeviceId, LoginThrottle.DimAccount, user.Username);
                if (ip is not null) await RecordThrottleFailAsync(session.DeviceId, LoginThrottle.DimIp, ip);
            }
            await session.SendAsync(new UserChangePasswordAck(session.NextSeq(), session.ServerTimestamp(),
                MsgType.UserChangePassword, false));
            return;
        }
        throttle?.Reset(LoginThrottle.DimAccount, user.Username); // 凭据成功同复位（仅账户维）
        user.PasswordHash = PasswordHasher.Hash(newPassword);
        user.UpdatedAt = _time.GetLocalNow().UtcDateTime;
        await db.SaveChangesAsync();
        await audit.WriteAsync("password_change", session.DeviceId, userId: userId);
        await session.SendAsync(new UserChangePasswordAck(session.NextSeq(), session.ServerTimestamp(),
            MsgType.UserChangePassword, true));
    }

    /// <summary>阶梯延迟（TimeProvider 版 Task.Delay——FakeTimeProvider 夹具推进假时钟即放行）。</summary>
    private async Task WaitThrottleAsync(int? delayMs)
    {
        if (delayMs is > 0)
            await Task.Delay(TimeSpan.FromMilliseconds(delayMs.Value), _time);
    }

    /// <summary>登录族开箱结果：Ok=取得明文；HardCut=缺 Box/明文非空（5004 硬切，07 §10.3）；
    /// Corrupt=解密失败（篡改/错钥——并入凭据失败口径，不泄漏原因）。</summary>
    private enum UnboxOutcome { Ok, HardCut, Corrupt }

    /// <summary>登录族密码开箱（M5-06/SEC-26，07 §10.3 硬切口径：无明文过渡双轨）。</summary>
    private static UnboxOutcome UnboxLoginPassword(ControlSession session, byte[]? box,
        string legacyPlain, out string password)
    {
        password = "";
        if (box is null || box.Length == 0 || legacyPlain.Length > 0)
            return UnboxOutcome.HardCut;
        try
        {
            password = Encoding.UTF8.GetString(session.UnboxLoginSecret(box));
            return UnboxOutcome.Ok;
        }
        catch (CryptographicException)
        {
            return UnboxOutcome.Corrupt;
        }
    }

    /// <summary>记一维失败+阶跃审计（07 §11.3：延迟值跨档才记——每窗 ≤5 条/键；detail=维名+键值+fails+delayMs）。</summary>
    private async Task RecordThrottleFailAsync(Guid? deviceId, string dim, string key)
    {
        var r = throttle!.RecordFailure(dim, key);
        if (!r.SteppedUp) return;
        object detail = dim == LoginThrottle.DimAccount
            ? new { dim, account = key, fails = r.Fails, delayMs = r.DelayMs }
            : new { dim, ip = key, fails = r.Fails, delayMs = r.DelayMs };
        await audit.WriteAsync("login_throttled", deviceId, detail: detail);
    }

    /// <summary>0x13 设备改名（本机管理类，passive 允许——02 §2.5 矩阵；FR-S-107）：
    /// trim 后空白或超 64 字符 → Ack Ok=false；成功改库 + 审计 + 0x41 推送（同账号 ∪ 共同分组，
    /// 与可见性同口径；发起端不收——本机前端由 PUT /api/device 成功路径自发 device_list 提示）。</summary>
    public async Task HandleDeviceUpdateAsync(ControlSession session, DeviceUpdate msg)
    {
        var name = msg.DeviceName.Trim();
        if (name.Length is < 1 or > 64)
        {
            await session.SendAsync(new DeviceUpdateAck(session.NextSeq(), session.ServerTimestamp(),
                MsgType.DeviceUpdate, false));
            return;
        }
        await using var db = await dbFactory.CreateDbContextAsync();
        await db.Devices.Where(d => d.Id == session.DeviceId)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.DeviceName, name));
        await audit.WriteAsync("device_rename", session.DeviceId, userId: session.OwnerUserId,
            detail: new { DeviceName = name });
        await session.SendAsync(new DeviceUpdateAck(session.NextSeq(), session.ServerTimestamp(),
            MsgType.DeviceUpdate, true));
        // Ack 先于推送（M2-10 纪律）：0x41 提示帧，接收端 refetch 0x40
        if (listPusher is not null)
            await listPusher.NotifyDevicesAsync(
                await DeviceListPusher.ResolveAccountPeersAsync(db, session.DeviceId));
    }
}
