<script setup lang="ts">
// 简易版·概览（FR-C-810）：本机卡（在线/设备名/远程码可复制）+ 实时速率卡（WS 速率总和）
// + 映射健康计数卡（失败标红可点 → /simple/mappings 处理）+ 新建映射 CTA。
// 监控集=用户批复"推荐集"：在线状态/远程码/映射健康计数/实时总速率；虚拟 IP 不在此卡
// ——以「连接地址 虚拟IP:本地端口」随映射卡呈现（简易版映射页，FR-C-810 调研定稿）。
import { computed, onMounted } from "vue";
import { useRouter } from "vue-router";
import { CodeText } from "@p2p/ui-shared";
import { useSystemStore } from "../../stores/system";
import { useMappingStore } from "../../stores/mappings";
import { humanRate } from "../mappingDetail";

const system = useSystemStore();
const mappings = useMappingStore();
const router = useRouter();

const device = computed(() => system.device);
const online = computed(() => system.state?.serverReachable ?? false);
const overview = computed(() => mappings.overview);

/** 实时总速率（WS mapping_stats 直写行内求和；无数据时卡片示空态文案）。 */
const totalRate = computed(() => {
  let up = 0;
  let down = 0;
  for (const r of mappings.rates.values()) {
    up += r.rateUp;
    down += r.rateDown;
  }
  return { up, down };
});
const hasRate = computed(() => mappings.rates.size > 0);

/** CTA：去映射页并直接开引导式向导（?create=1）。 */
function goCreate() {
  void router.push("/simple/mappings?create=1");
}

onMounted(() => {
  void system.refresh();
  void mappings.refresh();
});
</script>

<template>
  <section class="overview">
    <div class="cards">
      <el-card
        class="card"
        data-testid="simple-overview-device"
      >
        <template #header>
          本机
        </template>
        <div class="device-line">
          <span
            :class="['dot', online ? 'on' : 'danger']"
            role="img"
            :aria-label="online ? '在线' : '离线'"
          />
          <span class="device-name">{{ device?.deviceName ?? "本机" }}</span>
          <span class="muted">{{ online ? "在线" : "离线" }}</span>
        </div>
        <div
          v-if="device?.remoteCode"
          class="code-line"
        >
          <span class="muted">远程码</span>
          <CodeText
            :value="device.remoteCode"
            label="远程码"
            data-testid="simple-overview-code"
          />
        </div>
      </el-card>

      <el-card
        class="card"
        data-testid="simple-overview-rate"
      >
        <template #header>
          实时速率
        </template>
        <div
          v-if="hasRate"
          class="rate-big"
        >
          <div class="rate-item">
            <span class="arrow up">↑</span>{{ humanRate(totalRate.up) }}
          </div>
          <div class="rate-item">
            <span class="arrow down">↓</span>{{ humanRate(totalRate.down) }}
          </div>
        </div>
        <p
          v-else
          class="muted"
        >
          暂无数据（映射有流量后显示）
        </p>
      </el-card>

      <el-card
        class="card"
        data-testid="simple-overview-mappings"
      >
        <template #header>
          映射
        </template>
        <div class="map-total">
          共 {{ overview.total }} 条
        </div>
        <div class="map-breakdown">
          <span>直连 {{ overview.direct }}</span>
          <span>中继 {{ overview.relay }}</span>
          <span>打洞中 {{ overview.punching }}</span>
          <span>停用 {{ overview.disabled }}</span>
          <RouterLink
            v-if="overview.failed > 0"
            to="/simple/mappings"
            class="failed-link"
            data-testid="simple-overview-failed"
          >
            失败 {{ overview.failed }}，点此处理
          </RouterLink>
          <span
            v-else
            class="ok"
          >失败 0</span>
        </div>
      </el-card>
    </div>

    <div class="cta">
      <el-button
        type="primary"
        size="large"
        data-testid="simple-overview-create"
        @click="goCreate"
      >
        新建映射
      </el-button>
      <p class="muted">
        一步步引导完成；高级功能（日志/网段/设置等）请切右上角「高级版」
      </p>
    </div>
  </section>
</template>

<style scoped>
.cards {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 16px;
}
.device-line { display: flex; align-items: center; gap: 8px; }
.device-name { font-weight: 600; }
.dot { width: 8px; height: 8px; border-radius: 50%; background: var(--el-color-success); display: inline-block; }
.dot.danger { background: var(--el-color-danger); }
.code-line { margin-top: 12px; display: flex; align-items: center; gap: 8px; }
.rate-big { display: flex; flex-direction: column; gap: 6px; }
.rate-item { font-size: 22px; font-weight: 700; font-variant-numeric: tabular-nums; }
.arrow { margin-right: 8px; font-size: 16px; }
.arrow.up { color: var(--el-color-success); }
.arrow.down { color: var(--el-color-primary); }
.map-total { font-size: 22px; font-weight: 700; }
.map-breakdown {
  margin-top: 10px;
  display: flex;
  flex-wrap: wrap;
  gap: 4px 12px;
  font-size: 13px;
  color: var(--el-text-color-secondary);
}
.failed-link { color: var(--el-color-danger); text-decoration: none; font-weight: 600; }
.ok { color: var(--el-color-success); }
.cta { margin-top: 28px; text-align: center; }
.cta .muted { margin-top: 8px; }
</style>
