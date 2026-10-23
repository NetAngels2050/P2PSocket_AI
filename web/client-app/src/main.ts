import { createApp } from "vue";
import { createPinia } from "pinia";
import ElementPlus from "element-plus";
import "element-plus/dist/index.css";
import "element-plus/theme-chalk/dark/css-vars.css"; // EP 官方暗色变量（仅 html.dark 生效——简易版科技感深色皮肤用，高级版浅色不受影响）
import "@p2p/ui-shared/styles.css"; // 共享样式层（2026-10-20 评估批次 B：.toolbar/.muted/.error/.dot/.code-pill）
import App from "./App.vue";
import { router } from "./router";
import { bootstrapWebToken } from "./api";

// MSW 接入（M1-03）：VITE_USE_MSW=1 时启用 mock（前端独立开发联调，06 §5）
async function enableMswIfRequested() {
  if (import.meta.env.VITE_USE_MSW === "1") {
    const { worker } = await import("./mocks/browser");
    await worker.start({ onUnhandledRequest: "bypass" });
  }
}

await enableMswIfRequested();
bootstrapWebToken(); // M5-12：自动打开 URL 的 token → sessionStorage（07 §14.2）

const app = createApp(App);
app.use(createPinia());
app.use(ElementPlus);
app.use(router);
app.mount("#app");
