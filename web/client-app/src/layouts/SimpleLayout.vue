<script setup lang="ts">
// 简易版布局（FR-C-810，2026-10-20 双模式批复）：默认入口 /simple——品牌位 +
// 「概览|端口映射|分组」顶部 tab + 右侧在线态/登录态/「高级版」切换；
// 内容区 960px 水平居中（用户指令"页面水平居中"）。
// App 级 useWs 断连告警经 provide("simpleAlert") 注入（简易版不经 AdminLayout 的 alert 条）；
// 网段冲突横幅与高级版同源（system store 驱动，FR-C-204）。
import { computed, inject, type Ref } from "vue";
import { useSystemStore } from "../stores/system";
import { useAuthStore } from "../stores/auth";
import SubnetConflictBanner from "../components/SubnetConflictBanner.vue";

const TABS = [
  { path: "/simple", label: "概览" },
  { path: "/simple/mappings", label: "端口映射" },
  { path: "/simple/groups", label: "分组" },
];

const system = useSystemStore();
const auth = useAuthStore();
const wsAlert = inject<Ref<string | undefined> | undefined>("simpleAlert", undefined);

const online = computed(() => system.state?.serverReachable ?? false);
const headerText = computed(() =>
  auth.me?.username
    ? `${auth.me.username}（${auth.me.mode === "normal" ? "已登录" : "哑节点"}）`
    : "未登录",
);
</script>

<template>
  <div class="simple-layout">
    <header class="simple-header">
      <div class="header-inner">
        <RouterLink
          to="/simple"
          class="brand"
        >
          P2P 客户端
        </RouterLink>
        <nav class="tabs">
          <RouterLink
            v-for="t in TABS"
            :key="t.path"
            :to="t.path"
            class="tab"
          >
            {{ t.label }}
          </RouterLink>
        </nav>
        <div class="header-right">
          <!-- 离线=异常语义红点（评估 V-3 离线色统一口径） -->
          <span
            :class="['dot', online ? 'on' : 'danger']"
            role="img"
            :aria-label="online ? '在线' : '离线'"
          />
          <span class="online-text">{{ online ? "在线" : "离线" }}</span>
          <span class="who">{{ headerText }}</span>
          <RouterLink
            to="/dashboard"
            class="advanced"
            data-testid="simple-advanced-link"
          >
            高级版
          </RouterLink>
        </div>
      </div>
    </header>
    <div
      v-if="wsAlert"
      class="ws-alert"
      role="alert"
      data-testid="simple-ws-alert"
    >
      {{ wsAlert }}
    </div>
    <main class="simple-main">
      <SubnetConflictBanner />
      <RouterView />
    </main>
  </div>
</template>

<style scoped>
.simple-layout { min-height: 100vh; display: flex; flex-direction: column; }
.simple-header {
  border-bottom: 1px solid var(--el-border-color-light);
  background: var(--el-bg-color);
  position: sticky;
  top: 0;
  z-index: 10;
}
.header-inner {
  max-width: 960px; /* 内容水平居中（用户指令） */
  margin: 0 auto;
  padding: 0 16px;
  height: 56px;
  display: flex;
  align-items: center;
  gap: 24px;
}
.brand {
  font-weight: 700;
  font-size: 15px;
  color: var(--el-text-color-primary);
  text-decoration: none;
}
.tabs { display: flex; gap: 4px; flex: 1; }
.tab {
  padding: 6px 14px;
  border-radius: var(--el-border-radius-base);
  color: var(--el-text-color-regular);
  text-decoration: none;
  font-size: 14px;
}
/* 前缀匹配会把 /simple 也激活在子路由——精确激活才高亮 */
.tab.router-link-exact-active { background: var(--el-color-primary-light-9); color: var(--el-color-primary); font-weight: 600; }
.tab:hover { background: var(--el-fill-color-light); }
.header-right { display: flex; align-items: center; gap: 10px; }
.dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--el-color-success);
}
.dot.danger { background: var(--el-color-danger); }
.online-text { font-size: 13px; }
.who { font-size: 13px; color: var(--el-text-color-secondary); }
.advanced {
  font-size: 13px;
  color: var(--el-color-primary);
  text-decoration: none;
  border: 1px solid var(--el-color-primary-light-5);
  border-radius: var(--el-border-radius-base);
  padding: 3px 10px;
}
.advanced:hover { background: var(--el-color-primary-light-9); }
.ws-alert {
  padding: 6px 16px;
  font-size: 13px;
  color: var(--el-color-danger);
  background: var(--el-color-danger-light-9);
  border-bottom: 1px solid var(--el-color-danger-light-8);
  text-align: center;
}
.simple-main {
  flex: 1;
  width: 100%;
  max-width: 960px;
  margin: 0 auto;
  padding: 20px 16px 40px;
  box-sizing: border-box;
}
</style>
