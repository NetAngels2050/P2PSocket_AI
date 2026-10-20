// 映射展示工具（简易版/高级版共用，2026-10-20 双模式 FR-C-810 上收自 Mappings.vue）：
// - detail 原文形如 "head" / "head: 附注"（客户端侧枚举，Puncher/MappingEngine 落账），
//   多失败以"；"串联——头映射中文、附注保留原文供排障对照（评估 U-3 口径）；
// - 路径中文化 direct/relay → 直连/中继（评估 U-2 统一词）；
// - 速率人性化（二进制分档，与 server-app punchChart 同口径）。
export const DETAIL_TEXT: Record<string, string> = {
  punch_timeout: "打洞超时",
  punch_error: "打洞出错",
  punch_failed: "打洞失败",
  proto_not_supported: "协议不支持",
  stun_failed: "STUN 探测失败",
  listen_failed: "本地监听失败",
  l3_not_permitted: "目标地址不在对端开放网段",
  relay_failed: "中继回退失败",
};

export function detailText(detail: string): string {
  const zh = (s: string) => DETAIL_TEXT[s.trim()] ?? s;
  const parts = detail.split(": ");
  if (parts.length === 1) return zh(parts[0]);
  const heads = parts.slice(0, -1).map((p) => p.split("；").map(zh).join("；"));
  return [...heads, parts[parts.length - 1]].join("：");
}

/** 路径列/状态行中文化：有 WS 路径取路径，无速率数据时按状态推断（direct）。 */
export function pathText(path: string | undefined, state: string): string {
  if (path === "direct" || (!path && state === "direct")) return "直连";
  if (path === "relay") return "中继";
  return "—";
}

export function humanRate(n: number): string {
  if (n >= 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MiB/s`;
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KiB/s`;
  return `${n} B/s`;
}
