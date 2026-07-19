# RiftMap

RiftMap is a Linux-only, rate-limited IPv4 TCP service mapper for authorized
inventory work. It combines raw SYN discovery with ordinary kernel TCP
connections for passive, server-first SSH, FTP, MySQL, SMTP, Redis, or
Postgres banners. It never sends client protocol data.

> Only scan addresses you own or are explicitly authorized to test. The
> operator is responsible for provider policy, local law, and the configured
> target files.

## Status and scope

This repository is an experimental MVP, not a production-ready scanner. The
portable core is covered by unit tests, and CI includes a namespace-isolated
Linux smoke test, but broader native-Linux accuracy and scale validation is
still required before operational use. See
[`KNOWN_LIMITATIONS.md`](KNOWN_LIMITATIONS.md).

The MVP supports one or more IPv4 TCP service endpoints per job, deterministic
endpoint ordering, up to three no-response rounds, mmap state, atomic
checkpoints, idempotent NDJSON export, application wire-byte pacing, and an
operator-applied `tc` hard ceiling. Live scans require Linux 5.10+, libpcap,
iproute2, and root or equivalent `CAP_NET_RAW`/`CAP_NET_ADMIN` capabilities.
Offline commands and tests are portable. IPv6, UDP, TLS, authentication, active
probes, distributed execution, and vulnerability detection are out of scope.

## Build

```sh
sudo apt-get install build-essential pkg-config libpcap-dev iproute2
cargo build --release
```

Rust 1.85 is the MSRV and is pinned in CI rather than forcing a local toolchain
override. x86_64 Linux is the runtime target; aarch64 Linux is a compile target.

## Safe workflow

Copy `config.example.toml` to the ignored `config.local.toml`, then replace the
documentation-only fixture ranges with your authorized targets. Input lines
are IPv4 addresses or CIDRs; blank lines, comments, and inline `#` comments are
accepted. For CIDR entries, subnet-directed broadcast addresses are removed
automatically; explicitly listed single IPs are preserved. Excludes always win.
For a step-by-step runbook, see [`docs/OPERATIONS.md`](docs/OPERATIONS.md).

```sh
riftmap validate-config -c config.local.toml
riftmap estimate -c config.local.toml
riftmap tc-template -c config.local.toml
# Review and apply the printed tc command yourself.
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

For development and CI-scale pipeline validation without network traffic, set
`[simulation].enabled=true`. Simulated scans materialize normal jobs, summaries,
events, exports, and reports, but skip raw sockets, pcap, `tc`, and interface
counters. Use `[simulation]` ratios to choose deterministic open, closed,
unreachable, and no-response distributions.

RiftMap never changes qdisc. With `require_tc=true`, it refuses a live scan
unless the root qdisc is TBF. The application budget defaults to 80% of the
provider rate and the suggested TBF ceiling to 85%. Estimated SYN wire cost is
the IPv4 packet plus 38 bytes for link framing, FCS, preamble, and IFG. Raw
SYN discovery and banner TCP connect attempts share the same application
token bucket; banner collection also keeps its configured CPS, concurrency, and
bounded queue limits. When `[budget].time_budget_secs` is set, `estimate`
reports the SYN bandwidth needed to fit that time, a suggested provider egress
setting, expected banner capacity, and budget bottlenecks. The budget is only an
estimation input; scans do not stop automatically when it is reached. Set
`budget.enforce_time_budget=true` or `scan.max_runtime_secs` when you want a
protective timeout.

## Target safety

Global unicast is allowed by default. RFC1918 ranges require
`allow_private=true`. Unspecified, loopback, link-local, shared address space,
documentation, benchmarking, multicast, reserved, and limited broadcast space
is always removed before a job is created. A job stores an immutable config,
cryptographic seed, target digest, network-order endpoint files (`targets.bin`,
`ports.bin`, `protocols.bin`), byte-per-endpoint `state.bin`,
byte-per-endpoint `banner_state.bin`, and atomic `checkpoint.json`.
Cookie-validated SYN-ACKs are streamed into the banner queue as they are
discovered, so large scans do not need to aggregate all open targets before
banner collection starts. Gracefully finished, interrupted, or timed-out scans
also atomically persist cumulative counts, banner queue/done counts, timeout
status, and completion status in `summary.json`. Cookie-validated SYN-ACK, RST,
and ICMP responses persist the observed SYN attempt, RTT, and conflicting
observation counts for export. On Linux, `summary.json` also records interface
TX packet and byte deltas observed across raw discovery and banner collection.
Raw SYN packets advertise an MSS derived from the bound interface MTU and are
transmitted with `sendmmsg` batches.

`events.ndjson` is at-least-once. `export` selects the latest deterministic
`result_id`, sorts it stably, and writes `results.ndjson` or `results.csv`; by
default only targets with a cookie-validated SYN-ACK are emitted. Export can
filter by state, protocol, and banner status. With `output_all=true`, a
completed job also emits synthesized closed, unreachable, and no-response
records for targets without events; incomplete jobs are rejected to avoid
classifying unsent targets as no-response. Degraded jobs with non-zero pcap
drops are also rejected for `output_all=true`, because no-response observations
cannot be treated as reliable negatives. `job status` and `job list` support
`--json` for schedulers and inventory pipelines. Explicit sharding is available
with `scan --shard-index N --shard-count M`; each shard materializes only its
assigned deterministic endpoint subset and records the shard metadata in
`checkpoint.json`. `report` summarizes job status plus protocol, banner status,
and software distributions from the event log.
On resume, open targets whose banner state is not done are queued again, while
done targets are skipped. Older jobs without `banner_state.bin` are backfilled
from `events.ndjson`.

More details:

- [`docs/SAFETY_MODEL.md`](docs/SAFETY_MODEL.md) explains target filtering,
  negative results, and rate-safety assumptions.
- [`docs/RESULT_SCHEMA.md`](docs/RESULT_SCHEMA.md) documents `events.ndjson`,
  `results.ndjson`, and `summary.json`.
- [`docs/VALIDATION.md`](docs/VALIDATION.md) defines smoke-test and native
  validation evidence, including the native lab artifact harness.
- [`docs/VALIDATION_RESULTS.md`](docs/VALIDATION_RESULTS.md) records validation
  evidence produced from this repository state.
- [`docs/SAMPLE_OUTPUT.md`](docs/SAMPLE_OUTPUT.md) shows representative CLI
  output.
- [`docs/ROADMAP.md`](docs/ROADMAP.md) tracks known feature and validation gaps.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
sudo -E bash scripts/netns-smoke.sh target/debug/riftmap
```

Integration tests must use network namespaces or reserved local lab ranges;
CI and examples must never scan the public Internet. Licensed under
`MIT OR Apache-2.0`.
