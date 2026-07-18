# RiftMap

RiftMap is a Linux-only, rate-limited IPv4 TCP service mapper for authorized
inventory work. It combines raw SYN discovery with ordinary kernel TCP
connections for passive, server-first SSH, FTP, or MySQL banners. It never
sends client protocol data.

> Only scan addresses you own or are explicitly authorized to test. The
> operator is responsible for provider policy, local law, and the configured
> target files.

## Status and scope

This repository is an experimental MVP, not a production-ready scanner. The
portable core is covered by unit tests, but the Linux raw-socket backend still
requires native-Linux integration and accuracy validation before operational
use. See [`KNOWN_LIMITATIONS.md`](KNOWN_LIMITATIONS.md).

The MVP supports one IPv4 TCP port and protocol per job, deterministic target
ordering, up to three no-response rounds, mmap state, atomic checkpoints,
idempotent NDJSON export, application wire-byte pacing, and an operator-applied
`tc` hard ceiling. Live scans require Linux 5.10+, libpcap, iproute2, and root
or equivalent `CAP_NET_RAW`/`CAP_NET_ADMIN` capabilities. Offline commands and
tests are portable. IPv6, UDP, TLS, authentication, active probes, distributed
shards, and vulnerability detection are out of scope.

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
accepted. Excludes always win.

```sh
riftmap estimate -c config.local.toml
riftmap tc-template -c config.local.toml
# Review and apply the printed tc command yourself.
riftmap doctor -c config.local.toml
riftmap scan -c config.local.toml --dry-run
riftmap scan -c config.local.toml
riftmap resume --job .riftmap/jobs/<scan-id>
riftmap export --job .riftmap/jobs/<scan-id>
```

RiftMap never changes qdisc. With `require_tc=true`, it refuses a live scan
unless the root qdisc is TBF. The application budget defaults to 80% of the
provider rate and the suggested TBF ceiling to 85%. Estimated SYN wire cost is
the IPv4 packet plus 38 bytes for link framing, FCS, preamble, and IFG.

## Target safety

Global unicast is allowed by default. RFC1918 ranges require
`allow_private=true`. Unspecified, loopback, link-local, shared address space,
documentation, benchmarking, multicast, reserved, and limited broadcast space
is always removed before a job is created. A job stores an immutable config,
cryptographic seed, target digest, network-order `targets.bin`, byte-per-target
`state.bin`, and atomic `checkpoint.json`.

`events.ndjson` is at-least-once. `export` selects the latest deterministic
`result_id`, sorts it stably, and writes `results.ndjson`; by default only
targets with a cookie-validated SYN-ACK are emitted. A non-zero pcap drop count
marks the job degraded, so no-response observations must not be treated as
reliable negatives.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Integration tests must use network namespaces or reserved local lab ranges;
CI and examples must never scan the public Internet. Licensed under
`MIT OR Apache-2.0`.
