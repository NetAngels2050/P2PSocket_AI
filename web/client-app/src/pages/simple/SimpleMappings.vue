<script setup lang="ts">
// 简易版·端口映射卡列表（FR-C-810）：连接地址（虚拟IP:本地端口，CodeText 可复制）+
// 目标设备名反查（/api/devices，拉不到回落裸远程码）+ 状态/路径/实时速率行 +
// 启停（停用带确认——评估 U-7 口径）/失败中文原因+内联重试/删除（确认）；编辑跳高级版。
// 新建走引导式向导（FR-C-811）；?create=1 自动开向导（概览 CTA 入口）。
import { computed, onMounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { ElMessage, ElMessageBox } from "element-plus";
import { ApiError, CodeText, StatusTag } from "@p2p/ui-shared";
import PassiveBanner from "../../components/PassiveBanner.vue";
import MappingWizard from "./MappingWizard.vue";
import { useMappingStore } from "../../stores/mappings";
import { useDeviceStore } from "../../stores/devices";
import { useSystemStore } from "../../stores/system";
import { detailText, humanRate, pathText } from "../mappingDetail";

const mappings = useMappingStore();
const devices = useDeviceStore();
const system = useSystemStore();
const route = useRoute();
const router = useRouter();

const wizardOpen = ref(false);
const isPassive = computed(() => system.device?.capability === "passive");

/** 目标设备名反查（哑节点拉不到设备列表时回落裸远程码）。 */
function deviceLabel(code: string): string {
  const d = devices.items.find((x) => x.remoteCode === code);
  return d ? `${d.deviceName}（${code}）` : code;
}

/** 连接地址 = 虚拟 IP:本地端口（映射监听绑虚拟 IP，与部署形态一致）。 */
function connectAddr(localPort: number): string {
  return `${system.device?.virtualIp ?? "127.0.0.1"}:${localPort}`;
}

function rate(id: string) {
  return mappings.rates.get(id);
}

// 停用侧二次确认（与高级版 Mappings.vue 同口径——评估 U-7：误触即断流量）
async function toggle(id: string, name: string, enabled: boolean) {
  if (!enabled) {
    try {
      await ElMessageBox.confirm(`停用映射"${name}"将立即中断其流量，确定停用？`, "停用确认", {
        type: "warning",
      });
    } catch {
      return; // 用户取消
    }
  }
  try {
    if (enabled) await mappings.enable(id);
    else await mappings.disable(id);
  } catch (e) {
    ElMessage.error(e instanceof ApiError ? e.message : "请求失败");
  }
}

async function retry(id: string) {
  try {
    await mappings.retry(id);
    ElMessage.info("已重新排队打洞");
  } catch (e) {
    ElMessage.error(e instanceof ApiError ? e.message : "请求失败");
  }
}

async function remove(id: string, name: string) {
  try {
    await ElMessageBox.confirm(`确定删除映射"${name}"？`, "删除确认", { type: "warning" });
  } catch {
    return; // 用户取消
  }
  try {
    await mappings.remove(id);
    ElMessage.success("已删除");
  } catch (e) {
    ElMessage.error(e instanceof ApiError ? e.message : "请求失败");
  }
}

/** 高级编辑：简易版不含编辑表单，跳高级版 /mappings（等价能力，FR-C-810 调研定稿）。 */
function editAdvanced() {
  void router.push("/mappings");
}

function onCommand(cmd: string | number | object, id: string, name: string) {
  if (cmd === "delete") void remove(id, name);
  else editAdvanced();
}

onMounted(() => {
  void mappings.refresh();
  void devices.refresh(); // 设备名反查（失败静默——回落裸码）
  void system.refresh();
  if (route.query.create === "1") wizardOpen.value = true;
});
</script>

<template>
  <section class="simple-mappings">
    <PassiveBanner />
    <div class="page-head">
      <h2>端口映射</h2>
      <el-button
        type="primary"
        :disabled="isPassive"
        data-testid="simple-mappings-new"
        @click="wizardOpen = true"
      >
        新建映射
      </el-button>
    </div>

    <div
      v-if="mappings.items.length"
      class="map-cards"
    >
      <el-card
        v-for="m in mappings.items"
        :key="m.mappingId"
        class="map-card"
        :data-testid="`map-card-${m.mappingId}`"
        :class="{ 'is-failed': m.state === 'failed' }"
      >
        <div class="card-row head">
          <span class="name">{{ m.name }}</span>
          <StatusTag :state="m.state" />
          <span class="spacer" />
          <el-switch
            :model-value="m.enabled"
            :disabled="isPassive"
            size="small"
            :aria-label="m.enabled ? '停用' : '启用'"
            :data-testid="`map-switch-${m.mappingId}`"
            @change="toggle(m.mappingId, m.name, $event as boolean)"
          />
          <el-dropdown
            trigger="click"
            @command="onCommand($event, m.mappingId, m.name)"
          >
            <el-button
              size="small"
              class="more"
              :aria-label="`更多操作：${m.name}`"
            >
              ⋯
            </el-button>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="edit">
                  高级编辑
                </el-dropdown-item>
                <el-dropdown-item
                  command="delete"
                  divided
                >
                  删除
                </el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
        <div class="card-row">
          <span class="row-label">连接地址</span>
          <CodeText
            :value="connectAddr(m.localPort)"
            label="连接地址"
            :data-testid="`map-addr-${m.mappingId}`"
          />
        </div>
        <div class="card-row">
          <span class="row-label">目标</span>
          <span>{{ deviceLabel(m.targetRemoteCode) }} · {{ m.proto.toUpperCase() }} :{{ m.targetPort }}<template v-if="m.targetAddr !== 'self'"> · {{ m.targetAddr }}</template></span>
        </div>
        <div class="card-row meta">
          <template v-if="rate(m.mappingId)">
            <span data-testid="map-rate">↑ {{ humanRate(rate(m.mappingId)!.rateUp) }} ↓ {{ humanRate(rate(m.mappingId)!.rateDown) }}</span>
            <span class="sep">·</span>
            <span>{{ pathText(rate(m.mappingId)!.path, m.state) }}</span>
          </template>
          <span
            v-else
            class="muted"
          >—</span>
        </div>
        <div
          v-if="m.state === 'failed'"
          class="card-row fail"
          :data-testid="`map-fail-${m.mappingId}`"
        >
          <span>失败原因：{{ detailText(m.detail ?? "") }}</span>
          <el-button
            size="small"
            type="primary"
            plain
            :disabled="isPassive"
            :data-testid="`map-retry-${m.mappingId}`"
            @click="retry(m.mappingId)"
          >
            重试
          </el-button>
        </div>
      </el-card>
    </div>
    <el-empty
      v-else
      description="还没有映射，点「新建映射」开始第一条"
    />

    <MappingWizard v-model="wizardOpen" />
  </section>
</template>

<style scoped>
.page-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;
}
.page-head h2 { margin: 0; }
.map-cards { display: flex; flex-direction: column; gap: 12px; }
.map-card.is-failed { border-color: var(--el-color-danger-light-5); }
.card-row {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 14px;
}
.card-row + .card-row { margin-top: 10px; }
.card-row.head .name { font-weight: 600; font-size: 15px; }
.spacer { flex: 1; }
.row-label {
  width: 64px;
  flex-shrink: 0;
  color: var(--el-text-color-secondary);
  font-size: 13px;
}
.meta { color: var(--el-text-color-secondary); font-size: 13px; font-variant-numeric: tabular-nums; }
.sep { color: var(--el-border-color); }
.fail {
  margin-top: 10px;
  padding: 8px 10px;
  border-radius: var(--el-border-radius-base);
  background: var(--el-color-danger-light-9);
  color: var(--el-color-danger);
  font-size: 13px;
}
.fail span { flex: 1; }
.more { padding: 4px 8px; }
</style>
