# Linux 客户端部署手册

> 适用版本：1.0.0　依据：NFR-31/33、设计 08 §3.2/§7、03 §5　随版交付（M4-07）
> 三种形态：**A. deb 包**（NFR-33，Debian/Ubuntu）／**B. rpm 包**（spec 交付，rpmbuild 环境构建）／**C. 手工 tar**（单文件直装，公网服务器现网形态）。
> 实机构建实录（deb 内容清单 125 行核对+SHA256）见任务清单 M4-03 修订记录。

## 0. 通用事实（三种形态共用）

| 项 | 值 |
|---|---|
| 数据目录 | `/etc/p2p-client/`（0700 root——settings/state/凭据/logs；代码硬编码 03 §5） |
| systemd 服务 | `p2p-client`（Restart=always/5s 崩溃自愈 FR-C-902；root 运行——TUN 需 CAP_NET_ADMIN） |
| 本地 Web/向导 | `http://127.0.0.1:7100`（仅回环；SSH 隧道或端口转发访问） |
| 依赖 | 免装 .NET（自包含单文件）；**iproute2**（TUN 地址配置）；内核 TUN 支持（`/dev/net/tun` 存在——云镜像默认有，容器内须显式挂 `/dev/net/tun`） |
| CLI 卸载命令 | `p2p-client --uninstall`（清 TUN 适配器+服务端 0x12 解绑）/`--unbind`/`--purge` |
| exe 与 wwwroot | **必须同目录**（SPA 静态托管按 AppContext.BaseDirectory 解析） |

首启：浏览器开 `http://127.0.0.1:7100/wizard` → 服务端地址 `<IP>:7000` → 注册。服务器本机跑客户端时打洞必被安全组挡（随机打洞端口不放行）——**该形态的常态承载是设备级中继回退**（Web 页设备列表开启「中继回退」）。

## 1. 形态 A：deb（Debian/Ubuntu）

### 1.1 构建（Debian/Ubuntu 机器上）

```bash
# 构建机（仓库根）：产出产物并上传到打包机（如公网服务器）
sh build/package.sh client-linux          # → out/client-linux/{p2p-client, wwwroot/, 端点清单} + tar.gz
# 打包机（Debian/Ubuntu）：
sh deploy/client-linux/build-deb.sh       # → out/p2p-client_1.0.0-1_amd64.deb（校验：dpkg-deb -c / -I）
```

安装布局：`/usr/lib/p2p-client/`（主程序+wwwroot）+ `/usr/bin/p2p-client`（符号链接）+ `/lib/systemd/system/p2p-client.service` + postinst 创建 `/etc/p2p-client/`（0700）。

### 1.2 安装/升级/卸载

```bash
sudo dpkg -i p2p-client_1.0.0-1_amd64.deb   # 首装：daemon-reload+enable，不 start——须向导注册后手工起
sudo systemctl start p2p-client             # 向导完成后启动
sudo dpkg -i p2p-client_<新版>_amd64.deb    # 升级：在跑则 postinst 自动 restart（POSIX inode 替换，无缝切版）
sudo dpkg -r p2p-client                     # 移除（保留 /etc/p2p-client 数据）
sudo dpkg -P p2p-client                     # 清除（连 /etc/p2p-client 一起删；先 --uninstall 解绑更干净）
```

首装不自动启动是**有意设计**：未注册的客户端起来只会空转重连——向导注册完成后 `systemctl start` 即进入运行。

### 1.3 验证

```bash
systemctl status p2p-client          # active (running)
ip link                              # 注册成功后出现 p2p 虚拟网卡（100.64.0.2/24）
ls /etc/p2p-client/logs/             # client-<日期>.log
curl -s http://127.0.0.1:7100/wizard | head -1    # 200
```

## 2. 形态 B：rpm

`deploy/client-linux/p2p-client.spec`（文件布局同 deb）。构建（CentOS/RHEL/openEuler 等，需 rpmbuild）：

```bash
rpmbuild -bb deploy/client-linux/p2p-client.spec   # 产物在 ~/rpmbuild/RPMS/x86_64/
sudo rpm -ivh p2p-client-1.0.0-1.x86_64.rpm        # 安装（%post 同 deb：enable 不 start）
sudo rpm -Uvh p2p-client-<新版>.rpm                 # 升级（%preun $1=1 不停服务，%post 切版重启）
sudo rpm -e p2p-client                              # 卸载（rpm 无 purge 两段：erase 即停+disable+清状态）
```

> spec 实机构建归环境依赖项（当前构建机无 rpmbuild，装包属系统变更须确认）；语义差异（无 purge 两段）已在 spec 内注记。

## 3. 形态 C：手工 tar（单文件直装）

公网服务器现网形态（与 deb 布局无关，直装目录自定）：

```bash
# 构建机
sh build/package.sh client-linux        # out/client-linux/P2PSocket-client-linux-v1.0.0.tar.gz
# 目标机
sudo mkdir -p /opt/p2p/client && sudo tar -C /opt/p2p/client -xzf P2PSocket-client-linux-v1.0.0.tar.gz
sudo chmod +x /opt/p2p/client/p2p-client
# systemd 单元：参考 deploy/client/p2p-client.service（ExecStart 按实际部署位改）：
sudo tee /etc/systemd/system/p2p-client.service <<'EOF'
[Unit]
Description=P2P Client (virtual NIC + port mapping tunnel)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
WorkingDirectory=/opt/p2p/client
ExecStart=/opt/p2p/client/p2p-client
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload && sudo systemctl enable p2p-client   # 注册后再 start
```

- **升级**：停服务 → 覆盖 `p2p-client`+`wwwroot/`+端点清单（`/etc/p2p-client` 数据不动）→ 起服务（先备份旧二进制备回滚，同服务端 §2.5）；
- **卸载**：停+disable → `p2p-client --uninstall`（解绑+清 TUN）→ 删部署目录（数据目录按需保留）；
- 与 deb 的差异：无依赖声明（iproute2 须自查）、升级无自动 restart、布局自管。

## 4. 日常运维

```bash
systemctl status|restart p2p-client
journalctl -u p2p-client -f
tail -f /etc/p2p-client/logs/client-$(date +%Y%m%d).log
```

版本查看：Web「设置 → 关于」；协议不兼容自动开 `/upgrade` 引导页。

## 5. 常见问题速查

| 症状 | 处置（详见排障指南） |
|---|---|
| `--uninstall`/注册报 SIOCGIFINDEX/EINVAL | TUN 查询经 inet socket（已修复口径）；确认内核 `/dev/net/tun` 存在 |
| 打洞必 punch_timeout | 云安全组只放行固定端口，随机打洞端口被挡——开启**设备级中继回退**（该形态常态） |
| 7100 打不开 | 仅回环：`ssh -L 7100:127.0.0.1:7100 <主机>` 后本机访问 |
| 服务 Running 但未注册 | 正常——首装不 start 语义/未走向导；看 state.json 是否有设备凭据 |

## 修订记录

| 日期 | 说明 |
|---|---|
| 2026-10-10 | v1.0（M4-07）：deb 三命令族（装/升级/卸载双路径）+rpm spec 跑法与语义差异+手工 tar 直装（含现网 /opt/p2p/client 布局）+TUN/root 要求+云主机回退常态注记 |
