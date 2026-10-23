// M3-09/10 MSW mock（06 §5，server-app 域）：服务端 Web 端点镜像（认证三端点+仪表盘+四管理页
// 全端点）。带内存状态的工厂形态，供 Vitest 走查（自定义初始态）；动作端点真实改内存态
// （禁用翻转/解绑删行/重置码换值/审批移单入组/策略双写/配置部分更新），断言走查闭环。
// envelope { code, message, data }（04 §3：注意服务端字段名 message）；未认证 HTTP 401 {code:2001}
// ——与生产中间件形状一致（api.ts 拦截器按 -401/2001 跳登录）。
import { http, HttpResponse } from "msw";
import type {
  AuditLogView,
  BlacklistEntry,
  DashboardView,
  DeviceView,
  EncryptionView,
  GroupRequestView,
  GroupView,
  MappingView,
  RelaySessionsView,
  SecurityCountView,
  SecurityOverviewView,
  SecurityStunView,
  UserView,
} from "@p2p/ui-shared";

export interface MockServerState {
  authed: boolean;
  adminPassword: string; // 登录/改密校验（默认 admin/admin，FR-S-203）
  mustChangePassword: boolean; // 登录响应（仍是默认口令=true）
  dashboard: DashboardView;
  users: UserView[];
  devices: DeviceView[];
  groups: GroupView[];
  groupRequests: GroupRequestView[];
  mappings: MappingView[];
  config: Record<string, string>; // server_config 现值（白名单键）
  relaySessions: RelaySessionsView["sessions"]; // M3-11 /relay 会话表
  auditLogs: AuditLogView[]; // M3-11 /system 审计（id 升序存，端点降序出）
  alertTestCalls: string[]; // M5-07 alert-test 调用记录（目标 URL——mock 不真发，供断言闭环）
  blacklist: BlacklistEntry[]; // M5-09 安全中心黑名单（增删端点真实改此态）
  lockdownKicked: number; // M5-09 lockdown 响应 kicked（mock 固定值，断言用）
  securityCounts: { today: SecurityCountView; week: SecurityCountView; stun: SecurityStunView }; // M5-09 overview 计数节
  encryption: EncryptionView; // M5-13 静态加密状态（SEC-83——横幅用例可翻转）
}

/// 测试固定身份（过滤联动断言用稳定 UUID）
export const DEV_A = "11111111-1111-1111-1111-111111111111";
export const DEV_B = "22222222-2222-2222-2222-222222222222";
export const USER_ALICE = "33333333-3333-3333-3333-333333333333";
export const USER_BOB = "44444444-4444-4444-4444-444444444444";
export const GROUP_DEFAULT = "55555555-5555-5555-5555-555555555555";
export const GROUP_OFFICE = "66666666-6666-6666-6666-666666666666";
export const REQUEST_B = "77777777-7777-7777-7777-777777777777";
export const ADMIN_ID = "88888888-8888-8888-8888-888888888888";

function emptyDashboard(): DashboardView {
  return {
    onlineDevices: 0,
    groups: 1,
    mappings: { total: 0, enabled: 0, byStatus: { direct: 0, relay: 0, failed: 0, invalid: 0, unknown: 0 } },
    relay: { sessions: 0, bytesForwarded: 0, reaped: 0, startedAt: null, uptimeSec: 0 },
    stun: { admitted: 0, qps: 0, dropped: { rate: 0, auth: 0, circuit: 0 }, uptimeSec: 0 },
    punch: { total24h: 0, direct24h: 0, relay24h: 0, failed24h: 0, successRate24h: null, hourly: [] },
    version: { version: "1.0.0", commit: "m401mock", buildDate: "2026-10-07T00:00:00Z" }, // M4-01 角标
  };
}

export function createDefaultServerState(): MockServerState {
  return {
    authed: false,
    adminPassword: "admin",
    mustChangePassword: true,
    dashboard: {
      ...emptyDashboard(),
      onlineDevices: 3,
      groups: 2,
      mappings: { total: 5, enabled: 4, byStatus: { direct: 2, relay: 1, failed: 1, invalid: 0, unknown: 0 } },
      relay: { sessions: 1, bytesForwarded: 1048576, reaped: 2, startedAt: "2026-10-01T00:00:00Z", uptimeSec: 3725 },
      stun: { admitted: 3600, qps: 1.5, dropped: { rate: 12, auth: 3, circuit: 0 }, uptimeSec: 2400 },
      punch: {
        total24h: 40,
        direct24h: 30,
        relay24h: 6,
        failed24h: 4,
        successRate24h: 0.9,
        hourly: [
          { hourStart: 1759276800000, total: 0, success: 0 },
          { hourStart: 1759280400000, total: 10, success: 9 },
          { hourStart: 1759284000000, total: 20, success: 15 },
        ],
      },
    },
    users: [
      { id: ADMIN_ID, username: "admin", disabled: false, isAdmin: true, deviceCount: 0, createdAt: "2026-09-01T08:00:00Z" },
      { id: USER_ALICE, username: "alice", disabled: false, isAdmin: false, deviceCount: 2, createdAt: "2026-09-10T10:30:00Z" },
      { id: USER_BOB, username: "bob", disabled: true, isAdmin: false, deviceCount: 1, createdAt: "2026-09-12T14:00:00Z" },
    ],
    devices: [
      {
        deviceId: DEV_A, deviceName: "A 机", os: "windows", remoteCode: "712152",
        virtualIp: "100.64.0.2", ownerUsername: "alice", groups: ["默认分组"],
        online: true, disabled: false, createdAt: "2026-09-10T10:30:00Z",
      },
      {
        deviceId: DEV_B, deviceName: "B 机", os: "linux", remoteCode: "883456",
        virtualIp: "100.64.0.3", ownerUsername: "bob", groups: ["默认分组", "办公室"],
        online: false, disabled: false, createdAt: "2026-09-12T14:00:00Z",
      },
    ],
    groups: [
      {
        groupId: GROUP_DEFAULT, name: "默认分组", joinPolicy: "free", isDefault: true,
        ownerUsername: "admin", memberCount: 2, pendingCount: 0, createdAt: "2026-09-01T08:00:00Z",
      },
      {
        groupId: GROUP_OFFICE, name: "办公室", joinPolicy: "approval", isDefault: false,
        ownerUsername: "alice", memberCount: 1, pendingCount: 1, createdAt: "2026-09-11T09:00:00Z",
      },
    ],
    groupRequests: [
      {
        requestId: REQUEST_B, groupId: GROUP_OFFICE, groupName: "办公室", deviceId: DEV_B,
        deviceName: "B 机", ownerUsername: "alice", createdAt: "2026-09-30T16:20:00Z",
      },
    ],
    mappings: [
      {
        id: "aaaaaaaa-0000-0000-0000-000000000001", name: "网站", localPort: 8080, proto: "tcp",
        targetDeviceId: DEV_B, targetAddr: "self", targetPort: 80, enabled: true,
        createdAt: "2026-09-20T12:00:00Z", ownerDeviceId: DEV_A, ownerDeviceName: "A 机",
        ownerRemoteCode: "712152", targetDeviceName: "B 机",
        bytes: { up: 1048576, down: 2097152, relay: 0 },
        statsUpdatedAt: "2026-10-01T00:30:00Z", status: "direct",
      },
      {
        id: "aaaaaaaa-0000-0000-0000-000000000002", name: "文件服务", localPort: 2121, proto: "tcp",
        targetDeviceId: DEV_B, targetAddr: "self", targetPort: 21, enabled: true,
        createdAt: "2026-09-21T12:00:00Z", ownerDeviceId: DEV_A, ownerDeviceName: "A 机",
        ownerRemoteCode: "712152", targetDeviceName: "B 机",
        bytes: { up: 512, down: 1024, relay: 1536 },
        statsUpdatedAt: "2026-10-01T00:30:00Z", status: "relay",
      },
      {
        id: "aaaaaaaa-0000-0000-0000-000000000003", name: "归档 DNS", localPort: 53, proto: "udp",
        targetDeviceId: DEV_A, targetAddr: "10.0.0.5", targetPort: 53, enabled: false,
        createdAt: "2026-09-22T12:00:00Z", ownerDeviceId: DEV_B, ownerDeviceName: "B 机",
        ownerRemoteCode: "883456", targetDeviceName: "A 机",
        bytes: { up: 0, down: 0, relay: 0 },
        statsUpdatedAt: null, status: "unknown",
      },
    ],
    config: { registration_open: "1", default_join_policy: "free" },
    alertTestCalls: [],
    relaySessions: [
      {
        sid: "9007199254740993", // u64 超 JS 53 位精度示例（字符串承载）
        punchSessionId: "99999999-9999-9999-9999-999999999999",
        a: { deviceId: DEV_A, controlIp: "203.0.113.10:52001", udpAddr: "203.0.113.10:52001", carrier: "tcp" },
        b: { deviceId: DEV_B, controlIp: "203.0.113.20:52002", udpAddr: null, carrier: "pending" },
        bytesForwarded: 1048576,
        createdAt: "2026-10-01T01:00:00Z",
        lastActivity: "2026-10-01T01:05:00Z",
      },
    ],
    // 审计 25 行（分页走查：pageSize 20 → 2 页）；id 升序存储，端点 newest-first 降序输出
    auditLogs: Array.from({ length: 25 }, (_, i) => {
      const events = ["admin_login", "group_join", "group_join", "device_disable", "relay_config_change"];
      return {
        id: i + 1,
        ts: `2026-10-01T0${Math.floor(i / 12)}:${String(i % 12).padStart(2, "0")}:00Z`,
        event: events[i % events.length]!,
        deviceId: i % 3 === 0 ? DEV_A : null,
        userId: null,
        detail: i % 3 === 0 ? JSON.stringify({ macCode: `AA:BB:CC:00:00:${String(i).padStart(2, "0")}` }) : null,
      } satisfies AuditLogView;
    }),
    // M5-09 安全中心：黑名单（手动一条）+ lockdown 固定响应 + overview 计数节（命中四面）
    blacklist: [
      {
        ip: "203.0.113.99",
        reason: "扫描探测",
        source: "manual",
        createdAtUtc: "2026-10-22T08:00:00Z",
        expiresAtUtc: null,
      } satisfies BlacklistEntry,
    ],
    lockdownKicked: 2,
    securityCounts: {
      today: { loginFail: 2, register: 1, deny: 0 },
      week: { loginFail: 9, register: 4, deny: 2 },
      stun: { rate: 12, auth: 3, circuit: 0, since: "2026-10-20T00:00:00Z" },
    },
    encryption: { enabled: false, decryptFailures: 0 }, // M5-13 默认未配置（横幅警示路径）
  };
}

/// server_config 白名单默认值（DbInitializer.ConfigDefaults 同表；mock 只回 state.config 覆盖后的现值）
const CONFIG_DEFAULTS: Record<string, string> = {
  registration_open: "1",
  relay_enabled: "1",
  relay_rate_limit: "0",
  public_addr: "",
  stun_auth: "1",
  stun_alt_addr: "",
  virtual_subnet: "100.64.0.0/24",
  audit_retention_days: "90",
  log_level: "Information",
  max_devices: "500",
  device_registration_open: "1", // M5-02/SEC-61：设备注册准入开关
  register_rate_per_ip: "10", // M5-02/SEC-61：单 IP 注册频控 次/h
  login_fail_window_sec: "900", // M5-04/SEC-63：登录防爆破滑动窗（PUT 热更即时生效）
  login_delay_cap_ms: "8000", // M5-04/SEC-63：登录延迟封顶 ms
  autoban_enabled: "1", // M5-08/SEC-73：自动封禁判定开关（tick 现读；关判定不清条目）
  autoban_window_sec: "600", // M5-08：判定滑动窗（LoginThrottle IP 维共享源）
  autoban_fail_count: "20", // M5-08：窗内失败阈值
  autoban_duration_sec: "3600", // M5-08：auto 条目时长
  alert_enabled: "0", // M5-07/SEC-71：暂无接收端默认关（即时生效）
  alert_webhook_url: "",
  alert_window_sec: "300",
  alert_silence_sec: "1800",
  alert_login_fail_count: "10",
  alert_register_count: "5",
  alert_stun_drop_count: "200",
  control_conn_max_per_ip: "64", // M5-10/SEC-64：控制面并发闸（accept 现读即时生效）
  control_conn_max_total: "1024", // M5-10/SEC-64：控制面总并发上限
  relay_join_rate_per_ip: "30", // M5-10/SEC-64：中继 JOIN 到达速率 次/s/IP
  web_max_connections: "64", // M5-10/SEC-64：Web Kestrel 并发上限（重启生效）
  punch_retention_days: "90",
  stun_rate_per_ip: "50",
  stun_rate_per_device: "10",
  stun_circuit_pps: "2000",
  default_join_policy: "free",
  update_latest_version: "0.1.0",
  update_min_protocol: "1",
  update_url: "",
  update_artifact_sha256: "", // M5-14/SEC-84：产物哈希清单 JSON（空=未录入）
  update_notes: "",
};

const ok = (data: unknown) => HttpResponse.json({ code: 0, message: "ok", data });
// 与生产形状对齐：HTTP 400 + envelope（AdminSystemApi 等真回 400；HttpResponse.json 默认 200
// 会令错误走成功拦截器、文案落码表通用词——服务端 message 丢失，M3-11 走查抓出）
const badRequest = (message: string) =>
  HttpResponse.json({ code: 1001, message, data: null }, { status: 400 });
const unauthorized = () =>
  new HttpResponse(JSON.stringify({ code: 2001, message: "未登录或会话失效" }), {
    status: 401,
    headers: { "Content-Type": "application/json" },
  });

export function createServerHandlers(state: MockServerState) {
  return [
    http.post("*/api/auth/login", async ({ request }) => {
      const body = (await request.json()) as { username?: string; password?: string };
      if (body.username !== "admin" || body.password !== state.adminPassword)
        return new HttpResponse(JSON.stringify({ code: 2001, message: "用户名或密码错误" }), {
          status: 401,
          headers: { "Content-Type": "application/json" },
        });
      state.authed = true;
      return ok({ mustChangePassword: state.mustChangePassword });
    }),

    http.post("*/api/auth/change-password", async ({ request }) => {
      if (!state.authed) return unauthorized();
      const body = (await request.json()) as { oldPassword?: string; newPassword?: string };
      if (body.oldPassword !== state.adminPassword)
        return new HttpResponse(JSON.stringify({ code: 2001, message: "当前密码不正确" }), {
          status: 401,
          headers: { "Content-Type": "application/json" },
        });
      if ((body.newPassword ?? "").length < 6)
        return HttpResponse.json({ code: 1001, message: "新密码长度至少 6 位", data: null });
      state.adminPassword = body.newPassword!;
      state.mustChangePassword = false;
      return ok(null);
    }),

    http.post("*/api/auth/logout", () => {
      state.authed = false;
      return ok(null);
    }),

    http.get("*/api/dashboard", () => (state.authed ? ok(state.dashboard) : unauthorized())),

    // ── 用户（M3-03 端点形状）──────────────────────────────────────────
    http.get("*/api/users", ({ request }) => {
      if (!state.authed) return unauthorized();
      const url = new URL(request.url);
      const page = Math.max(1, Number(url.searchParams.get("page") ?? 1));
      const pageSize = Math.min(100, Math.max(1, Number(url.searchParams.get("pageSize") ?? 20)));
      const items = state.users.slice((page - 1) * pageSize, page * pageSize);
      return ok({ items, total: state.users.length, page, pageSize });
    }),

    http.post("*/api/users/:id/disable", ({ params }) => {
      if (!state.authed) return unauthorized();
      const u = state.users.find((x) => x.id === params.id);
      if (!u) return HttpResponse.json({ code: 1002, message: "用户不存在", data: null });
      if (u.isAdmin)
        return HttpResponse.json({ code: 1003, message: "不能禁用内置管理员（单管理员 D16）", data: null });
      u.disabled = true;
      return ok(null);
    }),

    http.post("*/api/users/:id/enable", ({ params }) => {
      if (!state.authed) return unauthorized();
      const u = state.users.find((x) => x.id === params.id);
      if (!u) return HttpResponse.json({ code: 1002, message: "用户不存在", data: null });
      u.disabled = false;
      return ok(null);
    }),

    http.put("*/api/users/:id/password-reset", ({ params }) => {
      if (!state.authed) return unauthorized();
      const u = state.users.find((x) => x.id === params.id);
      if (!u) return HttpResponse.json({ code: 1002, message: "用户不存在", data: null });
      if (u.isAdmin)
        return HttpResponse.json({
          code: 1003,
          message: "管理员密码请用 change-password 修改（Web 控制台本人操作）",
          data: null,
        });
      return ok({ tempPassword: "tmp-pw-x7k9" }); // 固定值便于走查断言
    }),

    // ── 设备（M3-04）──────────────────────────────────────────────────
    http.get("*/api/devices", () =>
      state.authed ? ok({ items: state.devices }) : unauthorized()),

    http.post("*/api/devices/:id/disable", ({ params }) => {
      if (!state.authed) return unauthorized();
      const d = state.devices.find((x) => x.deviceId === params.id);
      if (!d) return HttpResponse.json({ code: 1002, message: "设备不存在", data: null });
      d.disabled = true;
      d.online = false; // 踢线（AdminService 即时断连）
      return ok(null);
    }),

    http.post("*/api/devices/:id/enable", ({ params }) => {
      if (!state.authed) return unauthorized();
      const d = state.devices.find((x) => x.deviceId === params.id);
      if (!d) return HttpResponse.json({ code: 1002, message: "设备不存在", data: null });
      d.disabled = false;
      return ok(null);
    }),

    http.post("*/api/devices/:id/unbind", ({ params }) => {
      if (!state.authed) return unauthorized();
      const i = state.devices.findIndex((x) => x.deviceId === params.id);
      if (i < 0) return HttpResponse.json({ code: 1002, message: "设备不存在", data: null });
      state.devices.splice(i, 1); // 清理全集=行消失
      return ok(null);
    }),

    http.post("*/api/devices/:id/reset-remote-code", ({ params }) => {
      if (!state.authed) return unauthorized();
      const d = state.devices.find((x) => x.deviceId === params.id);
      if (!d) return HttpResponse.json({ code: 1002, message: "设备不存在", data: null });
      d.remoteCode = "NEW-CODE"; // 固定值便于走查断言
      return ok({ remoteCode: d.remoteCode });
    }),

    // ── 分组与审批（M3-05）────────────────────────────────────────────
    http.get("*/api/groups", () =>
      state.authed ? ok({ items: state.groups }) : unauthorized()),

    http.put("*/api/groups/default", async ({ request }) => {
      if (!state.authed) return unauthorized();
      const body = (await request.json()) as { policy?: string };
      if (body.policy !== "free" && body.policy !== "approval")
        return badRequest("参数错误（policy 须为 free|approval）");
      // 双写：键（下次建组口径）+ 默认分组行（存量即时生效）
      state.config.default_join_policy = body.policy!;
      const g = state.groups.find((x) => x.isDefault);
      if (g) g.joinPolicy = body.policy!;
      return ok({ policy: body.policy });
    }),

    http.get("*/api/group-requests", ({ request }) => {
      if (!state.authed) return unauthorized();
      const status = new URL(request.url).searchParams.get("status") ?? "pending";
      if (status !== "pending") return badRequest("参数错误（status 仅支持 pending）");
      return ok({ items: state.groupRequests });
    }),

    http.post("*/api/group-requests/:id/approve", ({ params }) => {
      if (!state.authed) return unauthorized();
      const i = state.groupRequests.findIndex((r) => r.requestId === params.id);
      if (i < 0) return HttpResponse.json({ code: 1002, message: "申请单不存在", data: null });
      const [r] = state.groupRequests.splice(i, 1);
      const g = state.groups.find((x) => x.groupId === r.groupId);
      if (g) {
        g.memberCount += 1;
        g.pendingCount = Math.max(0, g.pendingCount - 1);
      }
      return ok({ ok: true });
    }),

    http.post("*/api/group-requests/:id/reject", ({ params }) => {
      if (!state.authed) return unauthorized();
      const i = state.groupRequests.findIndex((r) => r.requestId === params.id);
      if (i < 0) return HttpResponse.json({ code: 1002, message: "申请单不存在", data: null });
      const [r] = state.groupRequests.splice(i, 1);
      const g = state.groups.find((x) => x.groupId === r.groupId);
      if (g) g.pendingCount = Math.max(0, g.pendingCount - 1);
      return ok({ ok: true });
    }),

    // ── 映射（M3-08；过滤=服务端 ?deviceId=/?status= 同口径）──────────
    http.get("*/api/mappings", ({ request }) => {
      if (!state.authed) return unauthorized();
      const q = new URL(request.url).searchParams;
      const deviceId = q.get("deviceId") ?? "";
      const status = q.get("status") ?? "";
      const items = state.mappings.filter(
        (m) => (!deviceId || m.ownerDeviceId === deviceId) && (!status || m.status === status),
      );
      return ok({ items, total: items.length });
    }),

    // ── 系统配置（M3-08；mock 白名单=全集键，校验示例口径）────────────
    http.get("*/api/system/config", () => {
      if (!state.authed) return unauthorized();
      const restartKeys = new Set([
        "public_addr", "stun_auth", "stun_alt_addr", "stun_rate_per_ip", "stun_rate_per_device",
        "stun_circuit_pps", "register_rate_per_ip", "log_level", "web_max_connections", // 与生产 RestartKeys 同口径（M5-02/M5-10）
      ]);
      return ok({
        items: Object.entries(CONFIG_DEFAULTS).map(([key, def]) => ({
          key,
          value: state.config[key] ?? def,
          restartRequired: restartKeys.has(key),
        })),
      });
    }),

    http.put("*/api/system/config", async ({ request }) => {
      if (!state.authed) return unauthorized();
      const body = (await request.json()) as Record<string, string>;
      if (!body || Object.keys(body).length === 0) return badRequest("参数错误（须提供至少一个配置键）");
      const ENUM_KEYS: Record<string, string[]> = {
        registration_open: ["0", "1"],
        relay_enabled: ["0", "1"],
        stun_auth: ["0", "1"],
        device_registration_open: ["0", "1"],
        alert_enabled: ["0", "1"],
        autoban_enabled: ["0", "1"],
        default_join_policy: ["free", "approval"],
        log_level: ["Trace", "Debug", "Information", "Warning", "Error", "Fatal"],
      };
      for (const [key, value] of Object.entries(body)) {
        if (!(key in CONFIG_DEFAULTS)) return badRequest(`参数错误（${key}：不在配置白名单内）`);
        const allowed = ENUM_KEYS[key];
        if (allowed && !allowed.includes(value))
          return badRequest(`参数错误（${key}：须为 ${allowed.join("|")}）`);
        // public_addr：IP 或域名（AdminSystemApi.Validators 同口径的 mock 简化，供校验错误走查）
        if (key === "public_addr" && value !== "" && !/^[a-zA-Z0-9.:-]+$/.test(value))
          return badRequest(`参数错误（${key}：须为 IP 或域名）`);
      }
      Object.assign(state.config, body);
      const restartKeys = new Set([
        "public_addr", "stun_auth", "stun_alt_addr", "stun_rate_per_ip", "stun_rate_per_device",
        "stun_circuit_pps", "register_rate_per_ip", "log_level", "web_max_connections", // 与生产 RestartKeys 同口径（M5-02/M5-10）
      ]);
      return ok({
        items: Object.entries(CONFIG_DEFAULTS).map(([key, def]) => ({
          key,
          value: state.config[key] ?? def,
          restartRequired: restartKeys.has(key),
        })),
      });
    }),

    // ── M5-07 告警测试推送（07 §13.1：须先配 URL；mock 不真发——记录目标供断言闭环）──
    http.post("*/api/security/alert-test", () => {
      if (!state.authed) return unauthorized();
      const url = state.config.alert_webhook_url ?? "";
      if (!url)
        return HttpResponse.json(
          { code: 1001, message: "参数错误（须先配置 alert_webhook_url）", data: null },
          { status: 400 },
        );
      state.alertTestCalls.push(url);
      return ok({ sent: true });
    }),

    // ── M5-09 安全中心（SEC-72、07 §13.2~§13.4）：overview 聚合/黑名单增删/lockdown ──
    http.get("*/api/security/overview", () => {
      if (!state.authed) return unauthorized();
      return ok({
        today: state.securityCounts.today,
        week: state.securityCounts.week,
        stun: state.securityCounts.stun,
        blacklist: state.blacklist,
        hits: { control: 3, stun: 1, relay: 0, web: 5 }, // 四面命中（mock 固定值）
        autoban: {
          enabled: (state.config.autoban_enabled ?? "1") === "1",
          windowSec: 600,
          failCount: 20,
          durationSec: 3600,
        },
        registrationOpen: (state.config.device_registration_open ?? "1") === "1",
        encryption: state.encryption, // M5-13（SEC-83、07 §14.3）：enabled=false=未配 masterKey
      } satisfies SecurityOverviewView);
    }),

    http.post("*/api/security/blacklist", async ({ request }) => {
      if (!state.authed) return unauthorized();
      const body = (await request.json()) as { ip?: string; reason?: string | null };
      if (!body?.ip || !/^[0-9a-fA-F:.]+$/.test(body.ip))
        return badRequest("参数错误（ip 须为合法地址）");
      if (!state.blacklist.some((e) => e.ip === body.ip))
        state.blacklist.push({
          ip: body.ip,
          reason: body.reason ?? "",
          source: "manual",
          createdAtUtc: "2026-10-23T12:00:00Z",
          expiresAtUtc: null,
        });
      return ok({ ip: body.ip });
    }),

    http.delete("*/api/security/blacklist/:ip", ({ params }) => {
      if (!state.authed) return unauthorized();
      const ip = String(params.ip);
      const i = state.blacklist.findIndex((e) => e.ip === ip);
      if (i < 0)
        return HttpResponse.json(
          { code: 1002, message: "条目不存在", data: null },
          { status: 404 },
        );
      state.blacklist.splice(i, 1);
      return ok({ ip });
    }),

    http.post("*/api/security/lockdown", () => {
      if (!state.authed) return unauthorized();
      return ok({ kicked: state.lockdownKicked });
    }),

    // ── 中继管理（M3-07 端点形状；config 现值走 state.config 两键）────────
    http.get("*/api/relay/sessions", () =>
      state.authed ? ok({ sessions: state.relaySessions }) : unauthorized()),

    http.get("*/api/relay/config", () => {
      if (!state.authed) return unauthorized();
      return ok({
        relayEnabled: (state.config.relay_enabled ?? "1") === "1",
        rateLimitBytes: Number(state.config.relay_rate_limit ?? "0"),
      });
    }),

    http.put("*/api/relay/config", async ({ request }) => {
      if (!state.authed) return unauthorized();
      const body = (await request.json()) as { relayEnabled?: boolean; rateLimitBytes?: number };
      if (body.relayEnabled === undefined && body.rateLimitBytes === undefined)
        return badRequest("参数错误（relayEnabled/rateLimitBytes 至少提供一项）");
      if (body.rateLimitBytes !== undefined && (body.rateLimitBytes < 0 || body.rateLimitBytes > 2147483647))
        return badRequest("参数错误（rateLimitBytes 须为 0~2147483647，0=不限）");
      if (body.relayEnabled !== undefined)
        state.config.relay_enabled = body.relayEnabled ? "1" : "0";
      if (body.rateLimitBytes !== undefined)
        state.config.relay_rate_limit = String(body.rateLimitBytes);
      return ok({
        relayEnabled: (state.config.relay_enabled ?? "1") === "1",
        rateLimitBytes: Number(state.config.relay_rate_limit ?? "0"),
      });
    }),

    // ── 审计日志（M3-08：newest-first + event 过滤 + 分页）────────────────
    http.get("*/api/audit-logs", ({ request }) => {
      if (!state.authed) return unauthorized();
      const q = new URL(request.url).searchParams;
      const page = Math.max(1, Number(q.get("page") ?? 1));
      const pageSize = Math.min(100, Math.max(1, Number(q.get("pageSize") ?? 20)));
      const event = q.get("event") ?? "";
      const rows = state.auditLogs
        .filter((a) => !event || a.event === event)
        .sort((x, y) => y.id - x.id); // newest-first（Id 自增=写入序）
      return ok({
        items: rows.slice((page - 1) * pageSize, page * pageSize),
        total: rows.length,
        page,
        pageSize,
      });
    }),
  ];
}
