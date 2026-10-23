// M1-32 API 单例（06 §1/§5）：同源部署（宿主 wwwroot 嵌入 + hash 路由 base './'），
// baseURL 留空走相对路径；测试经 VITE_API_BASE 指向 MSW 拦截源（node 下 axios 需绝对地址）。
// 路径常量一律取生成物（禁止手写字符串路径，06 §5）。
import { useApi } from "@p2p/ui-shared";

export const api = useApi(import.meta.env.VITE_API_BASE ?? "");

// M5-12/SEC-82 本地 Web 鉴权（07 §14.2）：宿主自动打开 URL 携带 ?token=，SPA 启动读取存
// sessionStorage（页面刷新存活；token 随服务重启轮换——sessionStorage 生命周期与之匹配，
// 不落 localStorage 防跨会话陈值）→ API 统一注入 Authorization: Bearer；WS 走 query
//（浏览器 WebSocket API 无法自定义头——07 §14.2 载体定案）。
export const WEB_TOKEN_KEY = "p2p-web-token";

/** 启动引导：URL ?token= → sessionStorage → 地址栏剥除（防历史/分享泄漏）。 */
export function bootstrapWebToken(): void {
  const url = new URL(location.href);
  const token = url.searchParams.get("token");
  if (!token) return;
  sessionStorage.setItem(WEB_TOKEN_KEY, token);
  url.searchParams.delete("token");
  history.replaceState(null, "", url.pathname + (url.search || "") + url.hash);
}

/** WS 完整地址（query token 注入；无 token 时裸址——服务端不可达提示兜底）。 */
export function buildWsUrl(path: string): string {
  const token = sessionStorage.getItem(WEB_TOKEN_KEY);
  const proto = location.protocol === "https:" ? "wss" : "ws";
  return `${proto}://${location.host}${path}${token ? `?token=${token}` : ""}`;
}

api.http.interceptors.request.use((config) => {
  const token = sessionStorage.getItem(WEB_TOKEN_KEY);
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});
