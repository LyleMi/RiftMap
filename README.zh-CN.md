# RiftMap

RiftMap 是用于获授权资产盘点的 Linux IPv4 TCP 服务测绘工具。它使用原始
SYN 做端口发现，再通过内核 TCP 连接被动读取 SSH、FTP 或 MySQL 的服务端首个
完整消息；不会发送客户端协议数据。

> 只能扫描自有或明确获授权的地址。云厂商政策、当地法律和目标文件均由操作者
> 负责确认。

## 范围与要求

当前仓库是实验性 MVP，并非可直接用于生产的扫描器。可移植核心已有单元测试，
但 Linux 原始套接字后端仍需在原生 Linux 上完成集成和准确性验证。已知差距见
[`KNOWN_LIMITATIONS.md`](KNOWN_LIMITATIONS.md)。

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

riftmap estimate -c config.local.toml
riftmap tc-template -c config.local.toml
# 审核并自行执行输出的 tc 命令
riftmap doctor -c config.local.toml
riftmap scan -c config.local.toml --dry-run
riftmap scan -c config.local.toml
riftmap resume --job .riftmap/jobs/<scan-id>
riftmap export --job .riftmap/jobs/<scan-id>
```

目标文件每行可写 IPv4 或 CIDR，支持空行与 `#` 注释，排除项优先。默认仅允许
全球单播；RFC1918 需要 `allow_private=true`。未指定、回环、链路本地、共享
地址、文档、基准、组播、保留和广播地址始终会在创建任务前移除。

程序不会自动修改 qdisc。`require_tc=true` 时，如果根 qdisc 不是 TBF，实扫
会被拒绝。默认应用预算是套餐出口的 80%，建议的 TBF 硬上限为 85%。若 pcap
发生丢包，任务会标记为 degraded，此时不能把无响应当成可靠的阴性结论。

任务目录保存不可变配置、随机 seed、目标摘要、网络序 `targets.bin`、每目标一
字节的 `state.bin` 和原子更新的 `checkpoint.json`。正常结束或中断的扫描还会将
累计计数和完成状态原子写入 `summary.json`。事件日志采用至少一次写入；
`export` 按确定性 `result_id` 去重并稳定输出。默认结果只包含出现过可信
SYN-ACK 的目标。启用 `output_all=true` 后，已完成任务还会为没有事件的目标
合成关闭、不可达和无响应结果；未完成任务会拒绝全量导出，避免把尚未发送的
目标误判为无响应。

Rust MSRV 为 1.85，仅在 CI 固定版本，不强制覆盖本机工具链。运行目标为
x86_64 Linux，同时进行 aarch64 Linux 编译验证。许可证为
`MIT OR Apache-2.0`。
