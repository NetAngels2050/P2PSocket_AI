// 项目说明常量（FR-C-812，2026-10-21）：简易版概览「关于项目」卡与高级版关于页
// 两处同源共用（防文案漂移——共享层上收先例 mappingDetail.ts/inviteCodeRule.ts）。
// 介绍文案基于根 README §1 口径；里程碑数据取根 README §6/任务清单索引
// （用户批复粒度：M1~M4 四条+维护期汇总一条，不随维护活动逐条展开）。

export const PROJECT_NAME = "AI-P2P";

export const PROJECT_DESC =
  "自部署的 P2P 内网穿透产品：把一台设备（服务方）上的内网服务，" +
  "经 P2P 打洞直连隧道暴露给另一台设备（访问方）。访问方连接 虚拟IP:本地端口，" +
  "流量经端到端加密隧道直达对端，无需公网中转；打洞失败时自动回退内置中继。" +
  "控制面集中、数据面 P2P，业务流量不经过服务端。基于 .NET 10 + Vue 3 构建。";

/** 仓库地址（git remote https 形式）。 */
export const PROJECT_REPO = "https://github.com/bobowire/P2PSocket_AI";

/** 用户交流 QQ 群（用户需求原文）。 */
export const PROJECT_QQ_GROUP = "417159195";

/** 里程碑时间轴节点：status=done 收官（success 绿）/ active 进行·收尾（primary 蓝）。 */
export interface MilestoneEntry {
  date: string;
  title: string;
  status: "done" | "active";
  note: string;
}

export const MILESTONES: MilestoneEntry[] = [
  {
    date: "2026-08-20 ~ 2026-09-12",
    title: "M1 · 核心链路可用",
    status: "done",
    note: "两台设备注册 + 第一条 UDP 直连映射打通（验收 A-1~A-4）",
  },
  {
    date: "2026-09-12 ~ 至今",
    title: "M2 · 打洞完整与授权闭环",
    status: "active",
    note: "TCP 打洞、中继回退、分组与远程码全量生效（35/38，余三项实机环境依赖）",
  },
  {
    date: "2026-09-30 ~ 至今",
    title: "M3 · 管理面与可观测",
    status: "active",
    note: "服务端 Web 后台全功能 + 性能观测（17/18，余两项实机验收）",
  },
  {
    date: "2026-10-07 ~ 2026-10-10",
    title: "M4 · 交付打磨",
    status: "done",
    note: "安装包 / deb·rpm / Docker / 基准报告 / 随版文档（10/10）",
  },
  {
    date: "2026-10-11 起",
    title: "维护期 · 持续交付",
    status: "active",
    note: "缺陷批次、设备改名、分组审批、Web 优化、双模式 UI、科技感皮肤、打洞直连优先等持续演进",
  },
];
