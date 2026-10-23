<script setup lang="ts">
// M2-29 升级提示页（06 §2、FR-C-904、OQ-5 手动升级不自动拉包）：协议版本不符被服务端
// 拒答时客户端自动打开（?reason=version，M2-26 拒答窗口→浏览器引导）；GET /api/upgrade/info
// 由本地代理现取或回落拒答缓存（UpgradeApi），数据到达即渲染 UpdateInfo 全量字段。
// M5-14（SEC-84、07 §14.4）：artifactSha256 清单 JSON 按本机平台取项展示（Windows→windows-setup
// /其余→linux-tar；本地 Web 浏览器与服务同机，userAgent 平台判定成立）；空/缺省/异形=不展示。
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import { ApiPaths, CodeText } from "@p2p/ui-shared";
import type { UpgradeInfoView } from "@p2p/ui-shared";
import { api } from "../api";

const route = useRoute();
const info = ref<UpgradeInfoView | null>(null);
const failed = ref(false);
const versionRejected = route.query.reason === "version";

onMounted(async () => {
  try {
    info.value = await api.get<UpgradeInfoView>(ApiPaths.UpgradeInfo);
  } catch {
    failed.value = true; // 本地服务不可达/未建立且无缓存
  }
});

/// 本机平台对应产物的 SHA-256（清单缺失/异形/无本平台项=null → 不展示）
const platformSha256 = computed(() => {
  const raw = info.value?.artifactSha256;
  if (!raw) return null;
  try {
    const map = JSON.parse(raw) as Record<string, unknown>;
    const key = navigator.userAgent.includes("Windows") ? "windows-setup" : "linux-tar";
    const hash = map[key];
    return typeof hash === "string" && /^[0-9a-f]{64}$/.test(hash) ? hash : null;
  } catch {
    return null; // 非法 JSON（服务端 PUT 已校验形状——此为双保险）
  }
});
</script>

<template>
  <section class="upgrade">
    <el-alert
      v-if="versionRejected"
      type="warning"
      :closable="false"
      show-icon
      data-testid="upgrade-reason-alert"
      title="协议版本不兼容"
      description="服务端已拒绝当前协议版本的连接（版本不符拒答窗口）。请下载并安装新版本，重启客户端后自动恢复。"
    />

    <el-card
      v-if="info"
      class="card"
      data-testid="upgrade-card"
    >
      <template #header>
        升级信息
      </template>
      <el-descriptions
        :column="1"
        border
      >
        <el-descriptions-item label="最新版本">
          <b data-testid="upgrade-version">{{ info.latestVersion }}</b>
        </el-descriptions-item>
        <el-descriptions-item label="协议兼容范围">
          <span data-testid="upgrade-protocol">{{ info.minProtocol }} ~ {{ info.maxProtocol }}</span>
          <span class="muted">（不兼容须升级，拒答窗口即由此触发）</span>
        </el-descriptions-item>
        <el-descriptions-item label="下载地址">
          <el-link
            v-if="info.upgradeUrl"
            type="primary"
            :href="info.upgradeUrl"
            target="_blank"
            data-testid="upgrade-url"
          >
            {{ info.upgradeUrl }}
          </el-link>
          <span
            v-else
            class="muted"
            data-testid="upgrade-url-empty"
          >未配置</span>
        </el-descriptions-item>
        <el-descriptions-item
          v-if="platformSha256"
          label="产物 SHA-256"
        >
          <div class="hash-cell">
            <CodeText
              :value="platformSha256"
              label="产物 SHA-256"
              data-testid="upgrade-hash"
            />
            <span class="muted">下载后请核验哈希一致（M5-14/SEC-84）</span>
          </div>
        </el-descriptions-item>
        <el-descriptions-item label="更新说明">
          <span
            class="notes"
            data-testid="upgrade-notes"
          >{{ info.notes }}</span>
        </el-descriptions-item>
      </el-descriptions>
      <p class="muted tip">
        手动升级：下载安装包后退出客户端（服务停止）再运行安装器；本页仅展示服务端下发的升级指引。
      </p>
    </el-card>

    <el-alert
      v-else-if="failed"
      type="error"
      :closable="false"
      show-icon
      title="暂无法获取升级信息"
      description="本地服务不可达，或控制通道未建立且无缓存（重启客户端后重试）。"
    />
  </section>
</template>

<style scoped>
.upgrade { max-width: 640px; }
.card { margin-top: 12px; }
.muted { color: var(--el-text-color-secondary); font-size: 12px; }
.notes { white-space: pre-line; }
.tip { margin: 12px 0 0; }
.hash-cell { display: flex; flex-direction: column; align-items: flex-start; gap: 4px; }
.hash-cell :deep(code) { word-break: break-all; letter-spacing: 0; }
</style>
