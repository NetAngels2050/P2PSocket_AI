// M5-09 安全中心页走查测试（任务清单完成判定：聚合卡片展示/黑名单增删/处置按钮流/端点鉴权）。
// 装配同 admin-ops.test.ts（MSW+pinia/router/ElementPlus 独立实例；confirm 按可见 overlay 过滤——
// ElMessageBox 关闭后 v-show 残留教训⑳；el-input attrs 透传落内部 input——M1-32 教训）。
import { setupServer } from "msw/node";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { flushPromises, mount, type VueWrapper } from "@vue/test-utils";
import { createPinia, setActivePinia, type Pinia } from "pinia";
import type { Router } from "vue-router";
import ElementPlus from "element-plus";
import { createAppRouter } from "../router";
import Security from "../pages/Security.vue";
import { useSecurityStore } from "../stores/security";
import { AUTH_KEY } from "../api";
import { createDefaultServerState, createServerHandlers, type MockServerState } from "../mocks/handlers";

const server = setupServer();
const live: VueWrapper[] = [];

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => {
  server.resetHandlers();
  for (const w of live.splice(0)) w.unmount();
  document.body.innerHTML = "";
  sessionStorage.clear();
});
afterAll(() => server.close());

async function mountAdminPage(
  component: Parameters<typeof mount>[0],
  state: MockServerState,
  initialPath: string,
): Promise<{ wrapper: VueWrapper; router: Router; pinia: Pinia }> {
  state.authed = true;
  server.use(...createServerHandlers(state));
  sessionStorage.setItem(AUTH_KEY, "1");
  const pinia = createPinia();
  setActivePinia(pinia);
  const router = createAppRouter();
  await router.push(initialPath);
  await router.isReady();
  const wrapper = mount(component, {
    global: { plugins: [pinia, ElementPlus, router] },
    attachTo: document.body,
  });
  live.push(wrapper);
  await flushPromises();
  return { wrapper, router, pinia };
}

function visibleBoxes(): HTMLElement[] {
  return [...document.querySelectorAll<HTMLElement>(".el-message-box")].filter(
    (b) => (b.closest(".el-overlay") as HTMLElement | null)?.style.display !== "none",
  );
}

async function clickConfirm(): Promise<void> {
  const btn = await vi.waitFor(() => {
    const vis = visibleBoxes();
    const b = vis[vis.length - 1]?.querySelector<HTMLElement>(".el-message-box__btns .el-button--primary");
    expect(b).not.toBeNull();
    return b!;
  });
  btn.click();
  await flushPromises();
  await flushPromises();
}

function boxMessage(): string {
  const vis = visibleBoxes();
  return vis[vis.length - 1]?.querySelector(".el-message-box__message")?.textContent ?? "";
}

function messages(): string {
  return [...document.querySelectorAll(".el-message")].map((m) => m.textContent ?? "").join("\n");
}

/** 概览定值后渲染（overview 未定值不渲染开关——ElSwitch null 教训） */
async function loaded(wrapper: VueWrapper): Promise<void> {
  await vi.waitFor(() => {
    expect(wrapper.findComponent('[data-testid="sec-register-switch"]').exists()).toBe(true);
  });
}

describe("安全中心走查", () => {
  it("聚合卡片展示：三计数卡今日+近 7 天、STUN 自启动累计口径、autoban 规则回显、四面命中、黑名单行", async () => {
    const state = createDefaultServerState();
    const { wrapper } = await mountAdminPage(Security, state, "/security");
    await loaded(wrapper);

    expect(wrapper.find('[data-testid="sec-loginfail-today"]').text()).toBe("2");
    expect(wrapper.find('[data-testid="sec-card-loginfail"]').text()).toContain("近 7 天 9 次");
    expect(wrapper.find('[data-testid="sec-register-today"]').text()).toBe("1");
    expect(wrapper.find('[data-testid="sec-deny-today"]').text()).toBe("0");

    const stun = wrapper.find('[data-testid="sec-card-stun"]');
    expect(stun.text()).toContain("自启动累计"); // 无时间窗事件源——口径标注（07 §13.2）
    expect(stun.text()).toContain("限速 12");
    expect(stun.text()).toContain("2026-10-20 00:00:00");

    expect(wrapper.find('[data-testid="sec-autoban-rule"]').text())
      .toContain("600s 窗内登录失败 ≥ 20 次 → 封禁 3600s");
    expect(wrapper.find('[data-testid="sec-actions"]').text()).toContain("控制面 3");
    expect(wrapper.find('[data-testid="sec-actions"]').text()).toContain("Web 5");

    const table = wrapper.find('[data-testid="sec-blacklist-table"]');
    expect(table.findAll(".el-table__row")).toHaveLength(1);
    expect(table.text()).toContain("203.0.113.99");
    expect(table.text()).toContain("扫描探测");
    expect(table.text()).toContain("手动");
    expect(table.text()).toContain("永久"); // manual 无到期
  });

  it("加黑流：dialog 填 IP+原因 → POST mock 落态 → 表格新行；非法 IP 400 提示且不入列", async () => {
    const state = createDefaultServerState();
    const { wrapper } = await mountAdminPage(Security, state, "/security");
    await loaded(wrapper);
    await wrapper.find('[data-testid="sec-block-btn"]').trigger("click");

    // el-dialog teleport 挂 body——经 document 定位（Login 改密弹窗同法）
    const dialog = await vi.waitFor(() => {
      const d = document.querySelector('[data-testid="sec-block-dialog"]');
      expect(d).not.toBeNull();
      return d!;
    });
    const ip = dialog.querySelector<HTMLInputElement>('[data-testid="sec-block-ip"]')!;
    const reason = dialog.querySelector<HTMLInputElement>('[data-testid="sec-block-reason"]')!;

    // 非法 IP：400 {1001} message 如实透出，名单不动
    ip.value = "not-an-ip";
    ip.dispatchEvent(new Event("input"));
    await flushPromises();
    (dialog.querySelector('[data-testid="sec-block-submit"]') as HTMLElement).click();
    await flushPromises();
    await vi.waitFor(() => expect(messages()).toContain("参数错误"));
    expect(state.blacklist).toHaveLength(1); // mock 态未增

    // 合法 IP+原因：入列 manual 永久 → 弹窗关 + 表格两行
    ip.value = "198.51.100.7";
    ip.dispatchEvent(new Event("input"));
    reason.value = "异常登录";
    reason.dispatchEvent(new Event("input"));
    await flushPromises();
    (dialog.querySelector('[data-testid="sec-block-submit"]') as HTMLElement).click();
    await flushPromises();
    const added = state.blacklist.find((e) => e.ip === "198.51.100.7");
    expect(added).toMatchObject({ reason: "异常登录", source: "manual", expiresAtUtc: null });
    await vi.waitFor(() =>
      expect(wrapper.find('[data-testid="sec-blacklist-table"]').text()).toContain("198.51.100.7"),
    );
    expect(wrapper.find('[data-testid="sec-blacklist-table"]').findAll(".el-table__row")).toHaveLength(2);
  });

  it("解封流：行按钮 → DELETE → mock 删行 + 表格空态", async () => {
    const state = createDefaultServerState();
    const { wrapper } = await mountAdminPage(Security, state, "/security");
    await loaded(wrapper);

    await wrapper.find('[data-testid="sec-unblock-203.0.113.99"]').trigger("click");
    await flushPromises();
    expect(state.blacklist).toHaveLength(0);
    await vi.waitFor(() =>
      expect(wrapper.find('[data-testid="sec-blacklist-table"]').text()).toContain("暂无封禁条目"),
    );
  });

  it("注册准入快切：switch → PUT device_registration_open → hint 随回读翻转（无 confirm）", async () => {
    const state = createDefaultServerState();
    const { wrapper } = await mountAdminPage(Security, state, "/security");
    const sw = await vi.waitFor(() => {
      const c = wrapper.findComponent('[data-testid="sec-register-switch"]');
      expect(c.exists()).toBe(true);
      return c as VueWrapper; // findComponent 返回 WrapperLike——收窄取 vm（新件零 tsc 增）
    });

    sw.vm.$emit("change", false);
    await flushPromises();
    expect(state.config.device_registration_open).toBe("0"); // 快切复用 system/config PUT
    await vi.waitFor(() =>
      expect(wrapper.find('[data-testid="sec-actions"]').text()).toContain("新设备注册被拒 4006"),
    );
  });

  it("踢全部会话：confirm 确认 → POST lockdown → 成功提示 kicked=2", async () => {
    const state = createDefaultServerState();
    const { wrapper } = await mountAdminPage(Security, state, "/security");
    await loaded(wrapper);

    await wrapper.find('[data-testid="sec-lockdown-btn"]').trigger("click");
    await vi.waitFor(() => expect(boxMessage()).toContain("断开全部在线控制会话"));
    await clickConfirm();
    await vi.waitFor(() => expect(messages()).toContain("已断开 2 个在线会话"));
  });

  it("端点鉴权：会话失效（401）→ 拦截器跳登录", async () => {
    const state = createDefaultServerState();
    const { pinia } = await mountAdminPage(Security, state, "/security");
    await loaded(live[live.length - 1]!);

    state.authed = false; // Cookie 过期 → 下次 overview 401
    const security = useSecurityStore(pinia);
    await security.refresh().catch(() => {});
    await vi.waitFor(() => expect(location.hash).toBe("#/login"));
    expect(sessionStorage.getItem(AUTH_KEY)).toBeNull();
  });
});
