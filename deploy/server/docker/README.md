# P2P 服务端 Docker 部署（M4-04，NFR-34、08 §3.3；M5-11 非 root 化）

镜像基于 `mcr.microsoft.com/dotnet/runtime-deps:10.0`（自包含单文件无需 SDK/Runtime 镜像），
程序全量在 `/app`（无状态），数据全在 `/data` 卷（SQLite `p2p.db` + WAL + server_config 业务键
`public_addr`/`stun_alt_addr`/`relay_*` 等 + 滚动日志 `/data/logs/`——镜像内 `/app/logs` 符号链接进卷，
08 §3.3"卷：/data（p2p.db+日志）"；迁移=搬卷）。

**M5-11 最小权限（SEC-81、07 §14.1）**：镜像 `USER p2p`（固定 uid 1000）非 root 运行；
3478 低端口绑定依赖容器 cap 集（Docker 默认 cap 含 NET_BIND_SERVICE）——若环境裁剪了 cap
须 `--cap-add=NET_BIND_SERVICE`；**`/data` 卷属主必须为 uid 1000**（见 §2 首启前一次性 chown；
root 属主旧卷直接换新镜像=库文件打不开起不来）。

## 1. 构建

本机构建产物后打镜像（上下文=out/server，产物目录整体 COPY）：

```sh
sh build/package.sh server                                  # 前端+publish 单文件自包含 → out/server
docker build -f deploy/server/docker/Dockerfile -t p2p-server:1.0.0 out/server
```

> 实机构建归 M4-10 环境依赖项（本机无 Docker；服务器装 Docker 属系统变更须确认）。

## 2. 启动（compose）

```sh
# M5-11：卷属主对齐镜像 uid 1000（既有 root 属主卷须一次性执行；新建目录可跳过）
sudo chown -R 1000:1000 ./data
cd deploy/server/docker
docker compose up -d
docker compose ps                 # healthy（TCP 7000 健康检查 ~30s 起）
docker logs p2p-server | head     # 首行「数据库就绪」
docker exec p2p-server id         # uid=1000(p2p)——非 root 运行核对（M5-11）
```

管理面：`http://127.0.0.1:7500`（宿主回环——compose 回环前缀映射，D11）；
跨机管理走 SSH 隧道 `ssh -L 7500:127.0.0.1:7500 <宿主>` 或客户端映射（口径同 M3-18 手工部署）。

首启初始化（08 §3.3 ③）：`/data/p2p.db` 自动建库（EF 迁移）+ 内置管理员 `admin/admin` + 默认分组
（FR-S-203/301）——**首登后立即改密**。日志：`./data/logs/app-YYYYMMDD.log`（随卷，10MB 滚动×保留期）。

## 3. 升级（换镜像不丢数据）

```sh
sh build/package.sh server
docker build -f deploy/server/docker/Dockerfile -t p2p-server:<新版本> out/server
cd deploy/server/docker
# 改 docker-compose.yml image tag → <新版本>
docker compose up -d              # 重建容器，./data 卷保持
```

数据库 schema 由 EF 迁移自动前滚（NFR-36）；回滚=换回旧 tag（跨版本回滚不建议，schema 只进不退）。

## 4. 数据迁移（换宿主机 / 卷换位）

```sh
# 源机：停服务后打包卷（SQLite WAL 安全点）
docker compose down
tar -czf p2p-data.tar.gz -C deploy/server/docker data
# 目标机：解回同位再 up
```

## 5. webBind 容器化口径（D11 不变量）

- 生产 `appsettings.json` 值 `listen.webBind=127.0.0.1`（systemd 部署=物理机回环，正确）。
- 容器内该值不可达宿主——Dockerfile 以环境变量 `listen__webBind=0.0.0.0` 覆盖，
  **仅作用于容器网络命名空间**；宿主侧 compose 映射 `127.0.0.1:7500:7500` 回环前缀，
  管理面在宿主网络栈上仍仅回环可达（与 D11 手工部署语义一致，双保险保持）。
- ⚠️ 不要把 ports 的 `127.0.0.1:` 前缀去掉——那会把管理面直接暴露公网。

## 6. 端口与安全组（同手工部署 08 §5.1）

公网放行：TCP 7000、TCP/UDP 3478、TCP/UDP 7010-7020；
**不放行 7500**（回环映射+安全组双保险）。`public_addr` 须配宿主公网 IP（中继 Grant 通告，
M2-36）——该键在 server_config（数据库），容器环境变量不覆盖业务键。
