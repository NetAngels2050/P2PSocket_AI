# P2P.Bench — L1 本地自动化基准 harness（M4-05）

> 依据：NFR-11/13/14、设计 09 §3、TD-24（基准环境分级）。
> **口径：in-proc 全链本机回环（L1）**——吞吐/延迟为基线测量 ≠ 真实网络性能；打洞矩阵为
> NatSimulator 语义确定性结果。真实网络数据归 L2 实机基准（公网 punch_stats 取数、两台 VPS
> iperf3 预留位），见基准测试报告（M4-06）。

## 跑法（手动；不进 CI 常规轮）

```bash
# 仓库根目录执行（输出 out/benchmark/*.csv + summary.md）
dotnet run --project src/Tools/P2P.Bench -c Release -- all

# 分段跑（逗号分隔多选）
dotnet run --project src/Tools/P2P.Bench -c Release -- matrix,punch-latency
# 可选段：matrix | punch-latency | throughput | rtt | concurrency | devices
```

- 全量 `all` 约 25~40 分钟（Windows 10/16 核参考值）；
- **稳定性判定**：重复跑两次，数据量级一致（相对量级而非逐毫秒一致——回环受本机负载影响）；
- 不进 CI 的原因：dotnet test 不发现 console 工程；全量时长与负载（本机回环打满）不适合常规轮，
  交付节点/回归敏感期手动跑（09 §3.4 节奏）；
- 分段落盘：每段完成即写 CSV（中断亦保留已完成段）；summary.md 在末尾整体写出。

## 世界装配（BenchWorld）

镜像 [ScenarioIntegrationTests](../../../tests/P2P.IntegrationTests/) in-proc 装配：
内存 SQLite 服务端（控制面+中继数据面+审计）+ 双 ClientRuntime（StubNicManager 替身，
`PunchBindOverride` 绑回环别名）+ NatSimulator（**与集成测试 link 编译同一源文件**，零拷贝
单一事实源）+ TCP echo 载荷终点。回环别名拓扑：模拟公网 127.0.0.1 / A=127.0.0.4 / B=127.0.0.5，
STUN 派生 :3478。

**每格/每样本独立世界**（独立库/服务端/客户端/NAT，销毁即隔离）——建立耗时样本无隧道残留，
矩阵格间零干扰。

## 基准项

| 段 | 输出 | 内容 |
|---|---|---|
| ① matrix | punch-matrix.csv | 打洞成功率矩阵：UDP=5 模式 5×5 全组合+UdpBlocked 代表对 2 格（N 恒 1，THello 连发口径 02 §5.1）；TCP=Seq/Random 4 组合×N=1~5（端口预测 02 §5.2）。每格独立世界+中继回退开（direct/relay/failed 三态+服务端 punch_stats 0x72 交叉列） |
| ② punch-latency | punch-latency.csv | 建立耗时分布（enable→终态墙钟）：direct（FC×FC UDP 承载）与 relay（SymmetricRandom×2 TCP 承载+回退）各 50 独立世界样本（轮询粒度 200ms 计入） |
| ③ throughput | throughput.csv | 单隧道吞吐回环基线：裸回环/direct-tcp-identity（恒等 NAT）/direct-tcp-predict（端口预测）/relay-tcp-fallback（SR×SR 预测 miss→中继回退，生产主路径）× 1 流大块/4 并发流/1 流小包（1KB×64K） |
| ④ rtt | rtt-ping.csv / rtt-echo.csv | 新增延迟（NFR-11 直连/中继分别测量）：直连+中继两世界 PTP PING（API 自报 avg）各 20 轮 + 隧道/中继/裸回环 TCP echo 64B×200（差值=封装/加密/分帧相对开销） |
| ⑤ concurrency | concurrency.csv | 8 映射并发 32MB each（建立到齐/全量完成/Mbps）+ 单映射 100 channel 复用（02 §4.5） |
| ⑥ resources | resources.csv | 全程 500ms 采样进程 CPU%/工作集/私有内存/句柄/线程（in-proc 全栈口径，NFR-13） |
| ⑦ devices | device-scale.csv | 服务端并发设备：真实 ControlClient（HELLO→Register→ECIES→Established→5s 心跳）批量注册 200/500 两档+稳态 15s 窗 CPU/内存（in-proc 标注） |

summary.md = 机器可读汇总（环境段+各段统计表），报告成文（M4-06）的数据源。

## 已知注意事项

- **严禁与 Integration 测试并行跑**：NatSimulator/回环别名端口族相同（127.0.0.2/127.0.0.4/…、
  :3478 STUN），并行互撞；
- ⑤ concurrency 段曾暴露控制通道并发发送 seq 乱序断连（P0，提交 2631a0c 修复）——该段即
  并发压力回归的现实参照；
- Windows 下 16 核参考吞吐：8 映射并发 ≈200Mbps 量级（回环含全栈加密/分帧）；
- `out/benchmark/` 不入库（out/ 已 ignore），CSV+summary 为交付报告的原始数据件。
