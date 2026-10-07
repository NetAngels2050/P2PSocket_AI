# M4-04 服务端 Docker 镜像（NFR-34、设计 08 §3.3、D11）。
# 构建上下文=out/server（package.sh server 目标产物，含 wwwroot+libe_sqlite3.so）：
#   docker build -f deploy/server/docker/Dockerfile -t p2p-server:1.0.0 out/server
# webBind 覆盖（D11 容器化口径）：生产 appsettings 值 127.0.0.1 在容器内不可达宿主映射——
#   经环境变量 listen__webBind=0.0.0.0 覆盖（Host.CreateApplicationBuilder 标准源，
#   键名 listen__webBind=节__属性）。仅容器网络命名空间内 0.0.0.0；宿主侧由 compose
#   回环前缀映射 "127.0.0.1:7500:7500" 保持管理面不对公网监听（双保险不破）。
FROM mcr.microsoft.com/dotnet/runtime-deps:10.0

WORKDIR /app

# 产物全量（p2p-server 单文件+wwwroot/+staticwebassets.endpoints.json+libe_sqlite3.so+appsettings.json）
COPY ./ ./

# Windows 构建机产物无执行位（tar/镜像层均保 0644）——容器内补 +x；
# 日志随 /data 卷（08 §3.3"卷：/data（p2p.db+日志）"）：代码日志路径=相对 cwd 的 logs/（Program.cs
# 硬编码无配置键）→ 镜像内符号链接 /app/logs→/data/logs。bind mount 遮蔽镜像层 /data 时，
# Serilog File sink 打开文件前自建父目录，首写自动重建 ./data/logs，无前置依赖。
RUN chmod +x p2p-server && ln -s /data/logs /app/logs

# 容器内覆盖（环境变量优先级高于 appsettings.json）：
#   webBind=0.0.0.0（见顶部注释）；数据库路径→/data 卷（无状态镜像，数据全在卷）
ENV listen__webBind=0.0.0.0 \
    database__path=/data/p2p.db

# 端口集（03 §5.1/08 §5.1）：控制 7000/STUN 3478 tcp+udp/中继 7010-7020 tcp+udp/管理 7500
# EXPOSE 为文档声明；实际发布由 run/compose -p 决定（7500 必须 127.0.0.1 前缀映射，见 compose）
EXPOSE 7000 3478/tcp 3478/udp 7010-7020/tcp 7010-7020/udp 7500

# 健康检查（runtime-deps 无 curl/wget：bash /dev/tcp 探 TCP 7000 控制面）
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD bash -c 'exec 3<>/dev/tcp/127.0.0.1/7000' || exit 1

ENTRYPOINT ["./p2p-server"]
