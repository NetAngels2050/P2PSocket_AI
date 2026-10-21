import { createRouter, createWebHashHistory, type RouteRecordRaw } from "vue-router";

// 路由表（06 §2）：六页面 M1-32 落地；/groups 全量替换占位 + /segments M2-28；
// /logs /upgrade M2-29（FR-C-807/904）。
// FR-C-810 双模式（2026-10-20）：默认入口 / → /simple（简易版顶部 tab 三页），
// 高级版十页原样可达——仪表盘挪 /dashboard（MENU 同步），其余路径不变。
// /about 关于页（FR-C-812，2026-10-21）：项目介绍/仓库/QQ 群+里程碑时间轴。
// routes 独立导出——测试构建隔离路由实例复用同表。
export const routes: RouteRecordRaw[] = [
  { path: "/", redirect: "/simple" },
  {
    path: "/simple",
    component: () => import("../layouts/SimpleLayout.vue"),
    children: [
      { path: "", component: () => import("../pages/simple/Overview.vue") },
      { path: "mappings", component: () => import("../pages/simple/SimpleMappings.vue") },
      { path: "groups", component: () => import("../pages/simple/SimpleGroups.vue") },
    ],
  },
  { path: "/dashboard", component: () => import("../pages/Dashboard.vue") },
  { path: "/wizard", component: () => import("../pages/Wizard.vue") },
  { path: "/login", component: () => import("../pages/Login.vue") },
  { path: "/devices", component: () => import("../pages/Devices.vue") },
  { path: "/groups", component: () => import("../pages/Groups.vue") },
  { path: "/segments", component: () => import("../pages/Segments.vue") },
  { path: "/mappings", component: () => import("../pages/Mappings.vue") },
  { path: "/logs", component: () => import("../pages/Logs.vue") },
  { path: "/settings", component: () => import("../pages/Settings.vue") },
  { path: "/upgrade", component: () => import("../pages/Upgrade.vue") },
  { path: "/about", component: () => import("../pages/About.vue") },
];

export const router = createRouter({
  history: createWebHashHistory(),
  routes,
});
