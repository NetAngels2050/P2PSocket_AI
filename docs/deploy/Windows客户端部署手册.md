# Windows 客户端部署手册

> 适用版本：1.0.0　依据：NFR-31/32、设计 08 §3.1/§7、03 §5　随版交付（M4-07）
> 两种形态：**A. 安装包 Setup exe**（NFR-32，推荐）／**B. portable 手工部署**（服务安装脚本，M1 起验证形态）。
> 本机部署实录见 [docs/部署文档/本机Windows客户端部署.md](../部署文档/本机Windows客户端部署.md)（保留作 M1-37 验收记录，最新口径以本手册为准）。

## 0. 通用事实（两种形态共用）

| 项 | 值 |
|---|---|
| 程序目录 | 形态 A=`C:\Program Files\P2PClient`；形态 B=任意无空格目录（如 `D:\P2PClient`） |
| 数据目录 | `C:\ProgramData\P2PClient`（settings.json/state.json/logs——**程序目录外，升级天然保留**） |
| Windows 服务 | `P2PClient`（LocalSystem——需加载 Wintun 驱动；开机自启+崩溃 5s×3 档自愈 FR-C-902） |
| 本地 Web/向导 | `http://127.0.0.1:7100`（**仅回环**，无需开防火墙端口） |
| 依赖 | 免装 .NET（自包含单文件）；**Wintun.dll 0.14.1 amd64 必须与 exe 同目录** |
| 映射监听 | 绑**虚拟 IP 100.64.0.2**（注册后 Wintun 适配器承载），非 127.0.0.1——排障看端口占用时勿混淆 |

## 1. 形态 A：安装包（推荐）

### 1.1 构建产物

```bash
# 构建机：需 Inno Setup 6（ISCC；winget install JRSoftware.InnoSetup）
# Wintun.dll 置于 out/wintun/Wintun.dll（官方 wintun.net 0.14.1，不入库——缺则脚本警告手工放置）
sh build/package.sh win-setup
# 产物：out/P2PClient-Setup-1.0.0-x64.exe（~36MB）
```

> 安装包未做代码签名：首次运行 Windows SmartScreen 可能弹"未知发布者"——「更多信息→仍要运行」。

### 1.2 安装（交互）

双击 Setup exe → UAC 确认 → 完成。安装器自动完成：

1. 全量落位 `%ProgramFiles%\P2PClient`（exe+wwwroot+Wintun.dll+端点清单）；
2. 创建数据目录 `%ProgramData%\P2PClient` 并设 ACL（SYSTEM/Administrators 完全控制；卸载不删数据）；
3. 创建并启动服务 `P2PClient`（sc create：binPath/start=auto/DisplayName/failure reset=86400 actions=restart/5000×3，与手工脚本逐参一致）；
4. 开始菜单「P2P Client → Web 管理页」快捷方式（`http://127.0.0.1:7100`）。

安装后打开 `http://127.0.0.1:7100/wizard` 走首启向导（服务端地址 `<IP>:7000` → 注册 → 虚拟网卡 100.64.0.2 出现即就绪）。

### 1.3 静默安装/卸载（批量部署）

```bat
P2PClient-Setup-1.0.0-x64.exe /VERYSILENT /SUPPRESSMSGBOXES     :: 静默安装（服务照装照启）
"C:\Program Files\P2PClient\unins000.exe" /VERYSILENT           :: 静默卸载（数据目录默认保留）
"C:\Program Files\P2PClient\unins000.exe" /VERYSILENT /PURGE    :: 静默卸载并删数据目录
```

### 1.4 升级与卸载

- **升级**：直接再跑新版 Setup（安装器先停既有服务→覆盖文件→重启服务；`%ProgramData%` 数据与凭据保留）。服务运行中覆盖会先等进程退出释放 exe/Wintun.dll 句柄。
- **卸载链**（安装器编排）：停服务 → `p2p-client --uninstall`（清 Wintun 适配器+服务端 0x12 解绑，M2-25）→ 删服务 → 数据目录去留（交互询问；`/PURGE` 强制删；静默默认保留）。

## 2. 形态 B：portable 手工部署

```text
① 构建：sh build/package.sh client-win        → out/client-win/{p2p-client.exe, wwwroot/, 端点清单}
② Wintun.dll：out/wintun/Wintun.dll 缺则从 https://www.wintun.net/builds/wintun-0.14.1.zip
   取 bin/amd64/wintun.dll 放入发布目录（与 exe 同目录）
③ 拷贝到目标目录（无空格路径，如 D:\P2PClient）：
   p2p-client.exe + Wintun.dll + staticwebassets.endpoints.json + wwwroot\
   + deploy/client/install-windows-service.ps1 / uninstall-windows-service.ps1
④ 安装服务：管理员 PowerShell 在该目录执行 .\install-windows-service.ps1
   （sc create P2PClient binPath start= auto DisplayName 'P2P Client'
     + failure reset= 86400 actions= restart/5000×3 + start）
⑤ 验证：Get-Service P2PClient = Running；http://127.0.0.1:7100/wizard = 200；
   C:\ProgramData\P2PClient\logs\ 有当日日志
```

- **升级**：停服务（`Stop-Service P2PClient`）→ 覆盖 exe+wwwroot+端点清单（Wintun.dll 与数据目录不动）→ 起服务；
- **卸载**：`.\uninstall-windows-service.ps1`（停+删服务）+ 建议再跑 `p2p-client.exe --uninstall` 清 Wintun 适配器与服务端绑定；
- 编码坑（实录）：仓库 ps1 为 UTF-8 无 BOM，Windows PowerShell 5.1 按 GBK 解析中文注释会语法崩——分发副本须重存**UTF-8 带 BOM**；.cmd 批处理保持纯 ASCII。

## 3. 日常运维

```powershell
Get-Service P2PClient                      # 状态（管理员）
Restart-Service P2PClient                  # 重启
Get-Content C:\ProgramData\P2PClient\logs\client-$(Get-Date -Format yyyyMMdd).log -Wait -Tail 20   # 日志跟随
```

- 版本查看：Web 管理页「设置 → 关于」（版本/构建提交/协议版本）；
- 协议不兼容时客户端自动打开 `/upgrade` 升级引导页（02 §7 链路冻结设计）。

## 4. 常见问题速查

| 症状 | 处置（详见排障指南） |
|---|---|
| 服务起不来/一启动即停 | 事件查看器+`C:\ProgramData\P2PClient\logs\`；Wintun.dll 缺失或与 exe 不同目录最常见 |
| 7100 打不开 | `Get-Service P2PClient` 是否 Running；仅回环——远程桌面场景在本机浏览器开 |
| 端口映射连不上 | 映射监听在 100.64.0.2 非 127.0.0.1；先 Web 页 ping-device 看隧道状态 |
| 升级后行为异常 | 「设置→关于」核对版本；旧版回滚=停服务换回备份 exe |

## 修订记录

| 日期 | 说明 |
|---|---|
| 2026-10-10 | v1.0（M4-07）：Setup 安装包全流程（M4-02 交付）+portable 手工形态（install-windows-service.ps1 口径）+静默参数/升级/卸载数据去留三路径 |
