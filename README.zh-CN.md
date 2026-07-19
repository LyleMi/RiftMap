# RiftMap

RiftMap 是用于获授权资产盘点的 Linux IPv4 TCP 服务测绘工具。它使用原始
SYN 做端口发现，再通过内核 TCP 连接被动读取 SSH、FTP、MySQL、SMTP、Redis 或
Postgres 的服务端首个完整消息；不会发送客户端协议数据。

> 只能扫描自有或明确获授权的地址。云厂商政策、当地法律和目标文件均由操作者
> 负责确认。

## 范围与要求

当前仓库是实验性 MVP，并非可直接用于生产的扫描器。可移植核心已有单元测试，
CI 也包含网络命名空间隔离的 Linux smoke test；投入运行前仍需要更广泛的原生
Linux 准确性与规模验证。已知差距见 [`KNOWN_LIMITATIONS.md`](KNOWN_LIMITATIONS.md)。

MVP 每个任务支持一个 TCP 端口和一种协议，提供确定性随机顺序、最多三轮仅对
无响应目标重试、mmap 状态、原子 checkpoint、幂等 NDJSON 导出、应用层线速
估算限速，以及由操作者自行应用的 `tc` 硬限速。实扫要求 Linux 5.10+、
libpcap、iproute2，以及 root 或等价的 `CAP_NET_RAW`/`CAP_NET_ADMIN` 权限。
不支持 IPv6、UDP、TLS、认证、主动协议探测、跨机分片和漏洞检测。

## 构建与使用

```sh
sudo apt-get install build-essential pkg-config libpcap-dev iproute2
cargo build --release
cp config.example.toml config.local.toml

riftmap validate-config -c config.local.toml
riftmap estimate -c config.local.toml
riftmap tc-template -c config.local.toml
# 审核并自行执行输出的 tc 命令
riftmap doctor -c config.local.toml
riftmap scan -c config.local.toml --dry-run
riftmap scan -c config.local.toml
riftmap scan -c config.local.toml --shard-index 0 --shard-count 4
riftmap job list -c config.local.toml
riftmap job list -c config.local.toml --json
riftmap job status --job .riftmap/jobs/<scan-id>
riftmap job status --job .riftmap/jobs/<scan-id> --json
riftmap report --job .riftmap/jobs/<scan-id>
riftmap report --job .riftmap/jobs/<scan-id> --json
riftmap validation-report -c config.local.toml --job .riftmap/jobs/<scan-id>
riftmap resume --job .riftmap/jobs/<scan-id>
riftmap export --job .riftmap/jobs/<scan-id>
riftmap export --job .riftmap/jobs/<scan-id> --state open --banner-status ok --format csv
riftmap job prune -c config.local.toml --older-than-days 30 --dry-run
```

完整操作手册见 [`docs/OPERATIONS.md`](docs/OPERATIONS.md)。

目标文件每行可写 IPv4 或 CIDR，支持空行与 `#` 注释，排除项优先。CIDR 条目
的子网定向广播地址会自动移除；显式列出的单个 IP 会保留。默认仅允许全球
单播；RFC1918 需要 `allow_private=true`。未指定、回环、链路本地、共享地址、
文档、基准、组播、保留和广播地址始终会在创建任务前移除。

程序不会自动修改 qdisc。`require_tc=true` 时，如果根 qdisc 不是 TBF，实扫
会被拒绝。默认应用预算是套餐出口的 80%，建议的 TBF 硬上限为 85%。raw SYN
发现和 banner TCP 连接尝试共享同一个应用 token bucket；banner 采集仍保留
单独配置的 CPS 和并发限制。若 pcap 发生丢包，任务会标记为 degraded，此时
不能把无响应当成可靠的阴性结论。`budget.enforce_time_budget=true` 会让扫描在
`time_budget_secs` 到达时保护性停止；也可以用 `scan.max_runtime_secs` 设置独立
运行时上限。
如需在实扫过程中动态调整应用层限速，可设置
`network.dynamic_application_mbps_file` 指向一个本地控制文件；文件内容为正数
Mbps，例如 `40`。RiftMap 会在扫描期间轮询该文件，文件缺失、为空或正在被改写时
保留上一次有效速率。该机制只调整应用 token bucket，不会修改主机 `tc` qdisc。

任务目录保存不可变配置、随机 seed、目标摘要、网络序 endpoint 文件
`targets.bin`、`ports.bin`、`protocols.bin`、每 endpoint 一字节的 `state.bin`
和原子更新的 `checkpoint.json`。正常结束或中断的扫描还会将
累计计数和完成状态原子写入 `summary.json`。通过 cookie 验证的 SYN-ACK、RST
和 ICMP 响应会持久化观测到的 SYN 尝试轮次、RTT 和冲突观察计数，用于导出。
Linux 下，`summary.json` 还会记录 raw 发现和 banner 采集期间的接口 TX 包数
与字节数增量。raw SYN 包会使用绑定接口 MTU 派生出的 MSS，并通过 `sendmmsg`
批量发送。事件日志采用至少一次写入；
`export` 按确定性 `result_id` 去重并稳定输出。默认结果只包含出现过可信
SYN-ACK 的目标，也可以按 state、protocol 和 banner status 过滤，并输出
`results.ndjson` 或 `results.csv`。启用 `output_all=true` 后，已完成任务还会
为没有事件的目标合成关闭、不可达和无响应结果；未完成任务会拒绝全量导出，
避免把尚未发送的目标误判为无响应。pcap 丢包导致的 degraded 任务也会拒绝
`output_all=true`，因为此时不能把无响应当成可靠的阴性结论。`job status` 和
`job list` 支持 `--json` 供调度器和资产流水线使用。显式分片可通过
`scan --shard-index N --shard-count M` 使用；每个分片只物化自己负责的确定性
endpoint 子集，并在 `checkpoint.json` 中记录分片元数据。
`report` 会基于事件日志汇总任务状态、协议、banner 状态和软件版本分布。

更多文档：

- [`docs/SAFETY_MODEL.md`](docs/SAFETY_MODEL.md)：目标过滤、阴性结果和限速安全假设。
- [`docs/RESULT_SCHEMA.md`](docs/RESULT_SCHEMA.md)：`events.ndjson`、`results.ndjson`
  和 `summary.json` 字段。
- [`docs/VALIDATION.md`](docs/VALIDATION.md)：smoke test、native Linux 验证证据和
  lab artifact 采集脚本。
- [`docs/VALIDATION_RESULTS.md`](docs/VALIDATION_RESULTS.md)：当前仓库状态已产出的
  验证证据。
- [`docs/SAMPLE_OUTPUT.md`](docs/SAMPLE_OUTPUT.md)：代表性的 CLI 输出示例。
- [`docs/ROADMAP.md`](docs/ROADMAP.md)：已知特性缺口和验证缺口。

Rust MSRV 为 1.85，仅在 CI 固定版本，不强制覆盖本机工具链。运行目标为
x86_64 Linux，同时进行 aarch64 Linux 编译验证。许可证为
`MIT OR Apache-2.0`。
