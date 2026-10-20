<script setup lang="ts">
// M1-32 设备发现（06 §2、FR-C-803）：可见设备表（在线/分组/远程码复制/开放网段）+
// "建映射"快捷按钮带入远程码跳转；按分组筛选。
// M2-28：设备级中继回退开关（/api/peers，D3 v0.4——目标设备层级，不经控制协议）；
// 列表刷新由 WS device_list 事件驱动（10s 轮询已移除，TD-16）。
import { computed, onMounted, ref } from "vue";
import { useRouter } from "vue-router";
import { ElMessage } from "element-plus";
import { ApiError, CodeText } from "@p2p/ui-shared";
import PassiveBanner from "../components/PassiveBanner.vue";
import { useDeviceStore, type DeviceItem } from "../stores/devices";
import { useSystemStore } from "../stores/system";

const devices = useDeviceStore();
const system = useSystemStore();
const router = useRouter();

const groupFilter = ref<string>("");

const groupOptions = computed(() => [
  ...new Set(devices.items.flatMap((d) => d.groups)),
].sort());

const filtered = computed(() =>
  groupFilter.value
    ? devices.items.filter((d) => d.groups.includes(groupFilter.value))
    : devices.items,
);

const isPassive = computed(() => system.device?.capability === "passive");

function createMapping(remoteCode: string) {
  void router.push({ path: "/mappings", query: { remoteCode } });
}

/** 切换中继回退（PUT /api/peers；打洞失败时是否允许经服务端中继兜底）。 */
async function toggleRelay(row: DeviceItem, value: string | number | boolean) {
  const on = value === true;
  try {
    await devices.setPeer(row.deviceId, on);
    ElMessage.success(`已${on ? "开启" : "关闭"}「${row.deviceName}」中继回退（对端打洞失败时${on ? "经中继转发" : "不再兜底"}）`);
  } catch (e) {
    ElMessage.error(e instanceof ApiError ? e.message : "请求失败");
  }
}

onMounted(() => void devices.refresh());
</script>

<template>
  <section class="devices">
    <PassiveBanner />
    <div class="toolbar">
      <h2>设备发现</h2>
      <el-select
        v-model="groupFilter"
        clearable
        placeholder="按分组筛选"
        class="group-filter"
        data-testid="devices-group-filter"
      >
        <el-option
          v-for="g in groupOptions"
          :key="g"
          :label="g"
          :value="g"
        />
      </el-select>
      <el-button @click="devices.refresh()">
        刷新
      </el-button>
    </div>
    <el-table
      :data="filtered"
      data-testid="devices-table"
      empty-text="暂无可见设备（需同账号或同分组）"
    >
      <el-table-column
        label="设备"
        min-width="160"
      >
        <template #default="{ row }">
          <span
            class="dot"
            :class="{ on: row.online }"
            role="img"
            :aria-label="row.online ? '在线' : '离线'"
          />
          {{ row.deviceName }}
        </template>
      </el-table-column>
      <el-table-column
        prop="virtualIp"
        label="虚拟 IP"
        width="120"
      />
      <el-table-column
        label="远程码"
        width="150"
      >
        <template #default="{ row }">
          <CodeText
            :value="row.remoteCode"
            label="远程码"
          />
        </template>
      </el-table-column>
      <el-table-column
        label="分组"
        min-width="140"
      >
        <template #default="{ row }">
          <el-tag
            v-for="g in row.groups"
            :key="g"
            size="small"
            class="tag"
          >
            {{ g }}
          </el-tag>
          <span v-if="row.groups.length === 0">—</span>
        </template>
      </el-table-column>
      <el-table-column
        label="开放网段"
        min-width="140"
      >
        <template #default="{ row }">
          <span v-if="row.lanSegments.length === 0">—</span>
          <code
            v-for="s in row.lanSegments"
            :key="s"
            class="code-pill"
          >{{ s }}</code>
        </template>
      </el-table-column>
      <el-table-column width="100">
        <template #header>
          <el-tooltip
            content="打洞失败时是否允许经服务端中继转发（目标设备级配置，D3）"
            placement="top"
          >
            中继回退
          </el-tooltip>
        </template>
        <template #default="{ row }">
          <el-switch
            :model-value="devices.peers[row.deviceId] ?? false"
            data-testid="devices-relay-fallback"
            @change="(v: string | number | boolean) => toggleRelay(row, v)"
          />
        </template>
      </el-table-column>
      <el-table-column
        label="操作"
        width="120"
        fixed="right"
      >
        <template #default="{ row }">
          <el-button
            size="small"
            type="primary"
            plain
            :disabled="isPassive"
            title="带入远程码新建映射"
            data-testid="devices-create-mapping"
            @click="createMapping(row.remoteCode)"
          >
            建映射
          </el-button>
        </template>
      </el-table-column>
    </el-table>
  </section>
</template>

<style scoped>
/* .toolbar / .dot / .muted / .code-pill（原 .seg）上收 ui-shared/styles/shared.css
   （2026-10-20 评估批次 B：离线色统一灰） */
.group-filter { width: 180px; }
.tag { margin-right: 4px; }
</style>
