using Microsoft.EntityFrameworkCore;
using P2P.Core.Crypto;

namespace P2P.Server.Data;

/// <summary>
/// 数据库初始化（03 §6：启动 Migrate 自动升级；§2 初始化种子）。
/// 顺序：先建 admin 用户，再建默认分组（owner=admin）。
/// </summary>
public static class DbInitializer
{
    /// <summary>内置管理员（FR-S-203，OQ-3：admin/admin，首登提示改密）。</summary>
    public const string AdminUsername = "admin";
    public const string DefaultGroupName = "默认分组";

    /// <summary>server_config 初始键值（03 §2.8，FR-S-825）。</summary>
    public static readonly (string Key, string Value)[] ConfigDefaults =
    [
        ("registration_open", "1"),
        ("relay_enabled", "1"),
        ("relay_rate_limit", "0"),
        ("public_addr", ""), // 中继端点通告地址（M2-36）：空=控制连接本地侧派生；NAT 云部署填公网 IP/域名
        ("stun_auth", "1"),
        ("stun_alt_addr", ""), // STUN 第二监听地址（M3-15 RFC5780 判型，05 §7.2）：空=单 IP 降级仅 mapping 可判；格式 IP:PORT（端口 0=UDP 随机 TCP 跟随）
        ("virtual_subnet", "100.64.0.0/24"),
        ("audit_retention_days", "90"),
        ("log_level", "Information"),
        ("max_devices", "500"),
        ("device_registration_open", "1"), // M5-02/SEC-61：设备注册准入开关（默认开放 OQ-20③；注册路径现读）
        ("register_rate_per_ip", "10"),    // M5-02/SEC-61：单 IP 注册频控 次/h（启动期读入 RegistrationGuard）
        ("login_fail_window_sec", "900"),  // M5-04/SEC-63：登录防爆破滑动窗（PUT 热更联动 LoginThrottle）
        ("login_delay_cap_ms", "8000"),    // M5-04/SEC-63：递增延迟封顶 ms（同上）
        ("autoban_enabled", "1"),          // M5-08/SEC-73：自动封禁判定开关（AlertPusher tick 现读，07 §13.3）
        ("autoban_window_sec", "600"),     // M5-08：判定滑动窗（与 LoginThrottle IP 维共享数据源）
        ("autoban_fail_count", "20"),      // M5-08：窗内失败阈值（达即加 auto 条目）
        ("autoban_duration_sec", "3600"),  // M5-08：auto 条目时长（过期自愈）
        // M5-07/SEC-71：告警通道（AlertPusher 每 tick 现读——PUT 后 ≤30s 生效，不占 RestartKeys）
        ("alert_enabled", "0"),            // OQ-21③：暂无接收端默认关；配 URL 后手动开
        ("alert_webhook_url", ""),         // 通用 JSON p2p.alert/v1（http/https 均可——可指向内网网关）
        ("alert_window_sec", "300"),       // 三类触发共用窗口
        ("alert_silence_sec", "1800"),     // 每类型静默窗（内不重复推送；0=不静默）
        ("alert_login_fail_count", "10"),  // login_fail_burst 阈值（登录族四入口 IP 维聚合）
        ("alert_register_count", "5"),     // register_burst 阈值（register+register_recover）
        ("alert_stun_drop_count", "200"),  // stun_drop_burst 阈值（StunGuard 三分桶窗口增量）
        // M5-10/SEC-64 监听面资源上限（07 §12）：控制面并发双键+中继 JOIN 速率 accept/到达时现读
        // 即时生效；web_max_connections 启动期读入 Kestrel Limits（改动须重启）
        ("control_conn_max_per_ip", "64"),   // 控制面单 IP 并发连接上限（accept 闸现读）
        ("control_conn_max_total", "1024"),  // 控制面总并发连接上限（同上）
        ("relay_join_rate_per_ip", "30"),    // 中继 JOIN 到达速率 次/s/IP（UDP/TCP 同源同桶）
        ("web_max_connections", "64"),       // 管理 Web Kestrel MaxConcurrentConnections（重启生效）
        ("punch_retention_days", "90"),
        ("stun_rate_per_ip", "50"),
        ("stun_rate_per_device", "10"),
        ("stun_circuit_pps", "2000"),
        ("default_join_policy", "free"), // FR-S-304：默认分组准入策略（free|approval）
        // 0x03 升级信息（M2-14，FR-S-804/OQ-5）：latest/min/url/notes 出配置，max=宿主编译协议版本
        ("update_latest_version", "0.1.0"),
        ("update_min_protocol", "1"),
        ("update_url", ""),           // M5-14/SEC-84：强制 https（PUT 拒 http；存量 http 运行时屏蔽，07 §14.4）
        ("update_artifact_sha256", ""), // M5-14/SEC-84：产物哈希清单 JSON {产物名→小写hex64}（0x03 现读下发）
        ("update_notes", ""),
    ];

    public static void Initialize(AppDbContext db)
    {
        db.Database.Migrate();

        // WAL + busy_timeout（03 §6；:memory: 库 journal_mode 保持 memory，不视为错误）
        try
        {
            db.Database.ExecuteSqlRaw("PRAGMA journal_mode=WAL;");
            db.Database.ExecuteSqlRaw("PRAGMA busy_timeout=5000;");
        }
        catch (Microsoft.Data.Sqlite.SqliteException)
        {
            // 内存库/只读场景忽略
        }

        Seed(db);
    }

    /// <summary>幂等种子：admin / 默认分组 / server_config 缺键补齐。</summary>
    public static void Seed(AppDbContext db)
    {
        var now = DateTime.UtcNow;

        var admin = db.Users.SingleOrDefault(u => u.Username == AdminUsername && u.IsAdmin);
        if (admin is null)
        {
            admin = new User
            {
                Id = Guid.NewGuid(),
                Username = AdminUsername,
                PasswordHash = PasswordHasher.Hash(AdminUsername), // OQ-3：admin/admin
                IsAdmin = true,
                CreatedAt = now,
                UpdatedAt = now,
            };
            db.Users.Add(admin);
            db.SaveChanges();
        }

        // 配置键先行补齐（幂等）：默认分组准入策略取 default_join_policy（FR-S-304）
        var existing = db.ServerConfig.Select(c => c.Key).ToHashSet();
        var missing = ConfigDefaults.Where(kv => !existing.Contains(kv.Key))
            .Select(kv => new ServerConfigEntry { Key = kv.Key, Value = kv.Value })
            .ToList();
        if (missing.Count > 0)
        {
            db.ServerConfig.AddRange(missing);
            db.SaveChanges();
        }

        if (!db.Groups.Any(g => g.IsDefault))
        {
            var policy = db.ServerConfig.AsNoTracking()
                .SingleOrDefault(c => c.Key == "default_join_policy")?.Value == "approval"
                ? "approval" : "free"; // 非法值回退 free
            db.Groups.Add(new Group
            {
                Id = Guid.NewGuid(),
                Name = DefaultGroupName,
                OwnerUserId = admin.Id,
                IsDefault = true,
                JoinPolicy = policy,
                CreatedAt = now,
            });
            db.SaveChanges();
        }
    }
}

/// <summary>server_config 类型化读取（缓存策略由宿主决定；M1 直读）。</summary>
public sealed class ServerConfigStore(AppDbContext db)
{
    public string Get(string key)
        => db.ServerConfig.AsNoTracking().SingleOrDefault(c => c.Key == key)?.Value
           ?? throw new InvalidOperationException($"server_config 缺键：{key}（初始化未执行？）");

    public bool GetBool(string key) => Get(key) == "1";
    public int GetInt(string key) => int.Parse(Get(key));
}
