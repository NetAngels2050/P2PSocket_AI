// M5-12/SEC-82 本地 Web token 注入（07 §14.2）：URL bootstrap → sessionStorage、
// 请求拦截器 Bearer 注入、buildWsUrl query 注入（WS 升级唯一浏览器载体）。
import { beforeEach, describe, expect, it } from "vitest";
import { api, bootstrapWebToken, buildWsUrl, WEB_TOKEN_KEY } from "../api";

describe("M5-12 本地 Web token（07 §14.2）", () => {
  beforeEach(() => {
    sessionStorage.clear();
    history.replaceState(null, "", "/");
  });

  it("bootstrapWebToken：URL ?token= → sessionStorage + 地址栏剥除（hash 保留）", () => {
    history.replaceState(null, "", "/wizard?token=abc123#/step1");
    bootstrapWebToken();
    expect(sessionStorage.getItem(WEB_TOKEN_KEY)).toBe("abc123");
    expect(location.pathname).toBe("/wizard");
    expect(location.search).not.toContain("token=");
    expect(location.hash).toBe("#/step1");
  });

  it("bootstrapWebToken：无 token 时不动地址栏", () => {
    history.replaceState(null, "", "/settings");
    bootstrapWebToken();
    expect(sessionStorage.getItem(WEB_TOKEN_KEY)).toBeNull();
    expect(location.pathname).toBe("/settings");
  });

  it("拦截器：已存 token → 请求注入 Authorization: Bearer", async () => {
    sessionStorage.setItem(WEB_TOKEN_KEY, "tok-xyz");
    let seen: unknown;
    await api.http.get("/probe", {
      // adapter 探针：不出网，直接捕获最终请求头
      adapter: async (config: { headers?: Record<string, unknown> }) => {
        seen = config.headers?.Authorization;
        return { data: {}, status: 200, statusText: "OK", headers: {}, config } as never;
      },
    } as never);
    expect(seen).toBe("Bearer tok-xyz");
  });

  it("拦截器：无 token → 不注入", async () => {
    let seen: unknown;
    await api.http.get("/probe", {
      adapter: async (config: { headers?: Record<string, unknown> }) => {
        seen = config.headers?.Authorization ?? null;
        return { data: {}, status: 200, statusText: "OK", headers: {}, config } as never;
      },
    } as never);
    expect(seen).toBeNull();
  });

  it("buildWsUrl：token 进 query；无 token 裸址", () => {
    sessionStorage.setItem(WEB_TOKEN_KEY, "tok-abc");
    expect(buildWsUrl("/ws/status")).toBe(`ws://${location.host}/ws/status?token=tok-abc`);
    sessionStorage.removeItem(WEB_TOKEN_KEY);
    expect(buildWsUrl("/ws/status")).toBe(`ws://${location.host}/ws/status`);
  });
});
