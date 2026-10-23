<script setup lang="ts">
// M5-09 安全中心页（06 §3、FR-S-827、SEC-72、07 §13.2~§13.4）：
// 概览卡（登录失败/新注册/授权拒绝——今日=UTC 日界+近 7 天=滚动 168h，血缘=audit_logs；
// STUN 丢弃=StunGuard 自启动累计无时间窗事件源，标注口径）+处置区（注册准入快切
// device_registration_open——Users 注册开关同款无 confirm 直接切+失败回读；自动封禁规则
// 回显；四面命中计数）+黑名单表（M5-08 端点增删；manual=永久/auto=定时 tag）+
// 踢全部会话（confirm——破坏性动作；07 §13.4 不设拒连窗，设备可立即重连）。
import { computed, onMounted, ref } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";
import type { BlacklistEntry } from "@p2p/ui-shared";
import { useSecurityStore } from "../stores/security";

const security = useSecurityStore();

const blockDialog = ref(false);
const blockIpDraft = ref("");
const blockReasonDraft = ref("");

/// overview 未定值不渲染开关/表格（ElSwitch 对 null 自纠偏 emit 误触——Users 教训同源）
const loaded = computed(() => security.overview !== null);

function hit(face: string): number {
  return security.overview?.hits[face] ?? 0; // 快照只含已触碰面——缺省 0
}

function fmtTime(iso: string | null): string {
  return iso ? iso.replace("T", " ").replace(/(\.\d+|Z|\+.*$)/, "").slice(0, 19) : "—";
}

async function onRegistrationChange(open: boolean) {
  try {
    await security.setRegistrationOpen(open);
    ElMessage.success(open ? "已开放设备注册" : "已关闭设备注册（既有设备不受影响）");
  } catch {
    await security.refresh(); // 失败回读现值（防 UI 与服务端漂移——Users 同款）
  }
}

async function openBlockDialog() {
  blockIpDraft.value = "";
  blockReasonDraft.value = "";
  blockDialog.value = true;
}

async function submitBlock() {
  const ip = blockIpDraft.value.trim();
  if (!ip) {
    ElMessage.error("请填写 IP 地址");
    return;
  }
  try {
    await security.blockIp(ip, blockReasonDraft.value);
    blockDialog.value = false;
    ElMessage.success(`已加黑 ${ip}（永久，立即生效）`);
  } catch (e) {
    ElMessage.error(e instanceof Error ? e.message : "加黑失败");
  }
}

async function unblock(row: BlacklistEntry) {
  try {
    await security.unblockIp(row.ip);
    ElMessage.success(`已解封 ${row.ip}`);
  } catch (e) {
    ElMessage.error(e instanceof Error ? e.message : "解封失败");
  }
}

async function onLockdown() {
  try {
    await ElMessageBox.confirm(
      "确定断开全部在线控制会话？设备可立即自动重连（不设拒连窗——长效封锁请用 IP 黑名单）。",
      "踢全部会话",
      { type: "warning" },
    );
  } catch {
    return; // 取消
  }
  try {
    const kicked = await security.lockdown();
    ElMessage.success(`已断开 ${kicked} 个在线会话`);
  } catch (e) {
    ElMessage.error(e instanceof Error ? e.message : "操作失败");
  }
}

onMounted(() => void security.refresh());
</script>

<template>
  <main class="page">
    <h2>安全</h2>

    <!-- M5-13 静态数据加密状态（SEC-83、07 §14.3）：未启用提示补配；在位但存在不可解行警示计数 -->
    <el-alert
      v-if="loaded && !security.overview!.encryption.enabled"
      data-testid="sec-enc-banner"
      class="sec-enc-alert"
      type="warning"
      :closable="false"
      show-icon
      title="静态数据加密未启用"
      description="未配置 security.masterKey（07 §14.3）——devices.device_secret 以明文存储（库文件权限为第一道防线）。补配后重启即启用并自动完成存量迁移。"
    />
    <el-alert
      v-else-if="loaded && security.overview!.encryption.decryptFailures > 0"
      data-testid="sec-enc-failures"
      class="sec-enc-alert"
      type="error"
      :closable="false"
      show-icon
      :title="`device_secret 解密失败 ${security.overview!.encryption.decryptFailures} 次（自启动累计）`"
      description="存在不可解密文行（配错钥或密文损坏）——相关设备凭据视为失效，恢复路径为解绑后重注册。"
    />

    <el-row
      v-if="loaded"
      :gutter="12"
      class="sec-cards"
    >
      <el-col :span="6">
        <el-card data-testid="sec-card-loginfail">
          <template #header>
            登录失败
          </template>
          <div class="sec-count">
            <span data-testid="sec-loginfail-today">{{ security.overview!.today.loginFail }}</span>
          </div>
          <div class="hint">
            今日 · 近 7 天 {{ security.overview!.week.loginFail }} 次
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card data-testid="sec-card-register">
          <template #header>
            新注册
          </template>
          <div class="sec-count">
            <span data-testid="sec-register-today">{{ security.overview!.today.register }}</span>
          </div>
          <div class="hint">
            今日 · 近 7 天 {{ security.overview!.week.register }} 次
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card data-testid="sec-card-deny">
          <template #header>
            授权拒绝
          </template>
          <div class="sec-count">
            <span data-testid="sec-deny-today">{{ security.overview!.today.deny }}</span>
          </div>
          <div class="hint">
            今日 · 近 7 天 {{ security.overview!.week.deny }} 次
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card data-testid="sec-card-stun">
          <template #header>
            STUN 丢弃（自启动累计）
          </template>
          <div class="sec-buckets">
            <span>限速 {{ security.overview!.stun.rate }}</span>
            <span>认证 {{ security.overview!.stun.auth }}</span>
            <span>断路 {{ security.overview!.stun.circuit }}</span>
          </div>
          <div class="hint">
            自 {{ fmtTime(security.overview!.stun.since) }} 启动累计（无时间窗事件源）
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-card
      v-if="loaded"
      class="sec-card-block"
      data-testid="sec-actions"
    >
      <template #header>
        安全态势与处置
      </template>
      <div class="sec-action-row">
        <span class="sec-label">设备注册准入</span>
        <el-switch
          :model-value="security.overview!.registrationOpen"
          data-testid="sec-register-switch"
          @change="onRegistrationChange"
        />
        <span class="hint">{{ security.overview!.registrationOpen ? "开放（新设备可注册）" : "关闭（新设备注册被拒 4006）" }}</span>
      </div>
      <div class="sec-action-row">
        <span class="sec-label">自动封禁</span>
        <el-tag
          :type="security.overview!.autoban.enabled ? 'success' : 'info'"
          data-testid="sec-autoban-state"
        >
          {{ security.overview!.autoban.enabled ? "开启" : "关闭" }}
        </el-tag>
        <span
          class="hint"
          data-testid="sec-autoban-rule"
        >{{ security.overview!.autoban.windowSec }}s 窗内登录失败 ≥ {{ security.overview!.autoban.failCount }} 次 → 封禁 {{ security.overview!.autoban.durationSec }}s（规则在「系统」页配置）</span>
      </div>
      <div class="sec-action-row">
        <span class="sec-label">黑名单命中</span>
        <span class="hint">
          控制面 {{ hit("control") }} · STUN {{ hit("stun") }} · 中继 {{ hit("relay") }} · Web {{ hit("web") }}（重启清零）
        </span>
      </div>
      <div class="sec-buttons">
        <el-button
          type="primary"
          data-testid="sec-block-btn"
          @click="openBlockDialog"
        >
          加黑 IP
        </el-button>
        <el-button
          type="danger"
          data-testid="sec-lockdown-btn"
          @click="onLockdown"
        >
          踢全部会话
        </el-button>
      </div>
    </el-card>

    <el-card
      v-if="loaded"
      class="sec-card-block"
    >
      <template #header>
        IP 黑名单（{{ security.overview!.blacklist.length }}）
      </template>
      <el-table
        :data="security.overview!.blacklist"
        data-testid="sec-blacklist-table"
      >
        <el-table-column
          prop="ip"
          label="IP"
          min-width="140"
        />
        <el-table-column
          label="来源"
          width="90"
        >
          <template #default="{ row }">
            <el-tag
              :type="row.source === 'manual' ? 'danger' : 'warning'"
              data-testid="sec-blacklist-source"
            >
              {{ row.source === "manual" ? "手动" : "自动" }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column
          prop="reason"
          label="原因"
          min-width="140"
        >
          <template #default="{ row }">
            {{ row.reason || "—" }}
          </template>
        </el-table-column>
        <el-table-column
          label="创建时间"
          width="170"
        >
          <template #default="{ row }">
            {{ fmtTime(row.createdAtUtc) }}
          </template>
        </el-table-column>
        <el-table-column
          label="到期"
          width="170"
        >
          <template #default="{ row }">
            {{ row.expiresAtUtc ? fmtTime(row.expiresAtUtc) : "永久" }}
          </template>
        </el-table-column>
        <el-table-column
          label="操作"
          width="100"
        >
          <template #default="{ row }">
            <el-button
              link
              type="primary"
              :data-testid="`sec-unblock-${row.ip}`"
              @click="unblock(row)"
            >
              解封
            </el-button>
          </template>
        </el-table-column>
        <template #empty>
          <el-empty description="暂无封禁条目" />
        </template>
      </el-table>
    </el-card>

    <el-dialog
      v-model="blockDialog"
      title="加黑 IP（手动=永久条目）"
      width="420px"
      data-testid="sec-block-dialog"
    >
      <el-form label-width="80px">
        <el-form-item label="IP">
          <el-input
            v-model="blockIpDraft"
            placeholder="如 203.0.113.10"
            data-testid="sec-block-ip"
          />
        </el-form-item>
        <el-form-item label="原因">
          <el-input
            v-model="blockReasonDraft"
            placeholder="选填（审计可见）"
            data-testid="sec-block-reason"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button
          data-testid="sec-block-cancel"
          @click="blockDialog = false"
        >
          取消
        </el-button>
        <el-button
          type="primary"
          data-testid="sec-block-submit"
          @click="submitBlock"
        >
          加黑
        </el-button>
      </template>
    </el-dialog>
  </main>
</template>

<style scoped>
.sec-enc-alert {
  margin-bottom: 12px;
}

.sec-cards {
  margin-bottom: 12px;
}

.sec-count {
  font-size: 26px;
  font-weight: 600;
  text-align: center;
}

.sec-buckets {
  display: flex;
  gap: 12px;
  justify-content: center;
  font-size: 14px;
}

.sec-buckets span {
  font-weight: 600;
}

.sec-card-block {
  margin-bottom: 12px;
}

.sec-action-row {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 10px;
}

.sec-label {
  min-width: 90px;
}

.sec-buttons {
  margin-top: 14px;
}
</style>
