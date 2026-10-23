// M5-09 安全中心 store（06 §3、FR-S-827、SEC-72、07 §13.2~§13.4）：overview 聚合快照
// （今日/近 7 天审计计数 + STUN 自启动累计 + 黑名单与四面命中 + autoban 现值 + 注册开关）+
// 黑名单增删（M5-08 端点）+ 处置动作（注册准入快切复用 system/config 单键 PUT、
// 踢全部会话 lockdown——不设拒连窗，设备凭 deviceSecret 立即重连）。处置后回读 overview。
import { ref } from "vue";
import { defineStore } from "pinia";
import { ServerApiPaths, apiPath, type SecurityOverviewView } from "@p2p/ui-shared";
import { api } from "../api";

export const useSecurityStore = defineStore("server-security", () => {
  const overview = ref<SecurityOverviewView | null>(null);

  async function refresh() {
    overview.value = await api.get<SecurityOverviewView>(ServerApiPaths.SecurityOverview);
  }

  /// 手动加黑（manual 永久条目；reason 可空）
  async function blockIp(ip: string, reason?: string) {
    await api.post(ServerApiPaths.SecurityBlacklist, { ip, reason: reason?.trim() || null });
    await refresh();
  }

  /// 解封（manual/auto 皆删行）
  async function unblockIp(ip: string) {
    await api.del(apiPath(ServerApiPaths.SecurityBlacklistByIp, { ip }));
    await refresh();
  }

  /// 注册准入快切：复用 /system/config 单键 PUT（M5-02 键即时生效）
  async function setRegistrationOpen(open: boolean) {
    await api.put(ServerApiPaths.SystemConfig, { device_registration_open: open ? "1" : "0" });
    await refresh();
  }

  /// 踢全部会话（07 §13.4）：返回断开数
  async function lockdown(): Promise<number> {
    const r = await api.post<{ kicked: number }>(ServerApiPaths.SecurityLockdown);
    await refresh();
    return r.kicked;
  }

  return { overview, refresh, blockIp, unblockIp, setRegistrationOpen, lockdown };
});
