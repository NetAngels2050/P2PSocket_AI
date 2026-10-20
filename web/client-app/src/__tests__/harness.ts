// 页面走查基架（自 pages.test.ts 上收——2026-10-20 双模式 FR-C-810：simple.test.ts 复用，
// 防复制漂移）：MSW 服务器 + attachTo 挂载逐用例拆净 + mountPage（独立 pinia/router/
// ElementPlus）+ ElMessageBox 定位。vitest 每文件独立 worker，两测试文件各引一份互不串台。
import { setupServer } from "msw/node";
import { expect, vi } from "vitest";
import { flushPromises, mount, type VueWrapper } from "@vue/test-utils";
import { createPinia, type Pinia } from "pinia";
import { createRouter, createWebHashHistory, type Router } from "vue-router";
import ElementPlus from "element-plus";
import { routes } from "../router";
import { createDefaultState, createHandlers, type MockState } from "../mocks/handlers";

const server = setupServer();
/** attachTo 挂载的页面（el-table/el-drawer 需文档流）逐用例拆净，防跨用例串台 */
const live: VueWrapper[] = [];

export { server, live };

export interface Mounted {
  wrapper: VueWrapper;
  router: Router;
  pinia: Pinia;
}

export async function mountPage(
  component: Parameters<typeof mount>[0],
  state: MockState = createDefaultState(),
  initialPath = "/",
): Promise<Mounted> {
  server.use(...createHandlers(state));
  const router = createRouter({ history: createWebHashHistory(), routes });
  await router.push(initialPath);
  await router.isReady();
  const pinia = createPinia();
  const wrapper = mount(component, {
    global: { plugins: [pinia, ElementPlus, router] },
    attachTo: document.body, // el-drawer/el-table 需真实文档流
  });
  live.push(wrapper);
  await flushPromises();
  return { wrapper, router, pinia };
}

/** 定位当前 ElMessageBox（按标题/正文文本过滤，取末位最新窗——旧窗关闭动画期可能仍在 DOM）
 * 并点确认/取消按钮。2026-10-20 批次 A 新增确认弹窗（登出/停用）后多测试共用。 */
export async function clickMessageBox(titleMark: string, button: "confirm" | "cancel") {
  const matched = () =>
    [...document.querySelectorAll(".el-message-box")]
      .filter((b) => b.textContent?.includes(titleMark));
  await vi.waitFor(() => expect(matched().length).toBeGreaterThan(0));
  const box = matched().pop() as HTMLElement;
  const sel = button === "confirm"
    ? ".el-message-box__btns .el-button--primary"
    : ".el-message-box__btns .el-button:not(.el-button--primary)";
  (box.querySelector(sel) as HTMLElement).click();
  await flushPromises();
}
