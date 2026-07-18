# Operations guide

RiftMap is intended for authorized IPv4 TCP inventory work. Treat every live
scan as a change to the network environment: prepare the target set, apply a
separate egress ceiling, run preflight checks, and keep the job directory until
export is complete.

## Prerequisites

- Linux 5.10 or newer.
- `libpcap`, `iproute2`, and root or equivalent `CAP_NET_RAW` and
  `CAP_NET_ADMIN` capabilities.
- A target file containing only networks you own or are explicitly authorized
  to test.
- A host-level or provider-level policy that permits the configured traffic.

Offline commands such as `estimate`, `tc-template`, and dry runs are portable.
Live scans are Linux-only.

## Standard workflow

```sh
cp config.example.toml config.local.toml
$EDITOR config.local.toml

cargo build --release
target/release/riftmap estimate -c config.local.toml
target/release/riftmap tc-template -c config.local.toml
# Review and apply the printed tc command yourself.
sudo target/release/riftmap doctor -c config.local.toml
sudo target/release/riftmap scan -c config.local.toml --dry-run
sudo target/release/riftmap scan -c config.local.toml
target/release/riftmap export --job .riftmap/jobs/<scan-id>
```

Use `resume` after Ctrl-C, timeout, or process failure:

```sh
sudo target/release/riftmap resume --job .riftmap/jobs/<scan-id>
```

The job stores an immutable `config.toml`, so resume and export use the
configuration captured when the job was created.

## Rate controls

RiftMap has two layers of rate control:

- Application pacing uses `provider_egress_mbps * application_ratio`.
- The `tc-template` command prints a TBF qdisc ceiling using
  `provider_egress_mbps * tc_ratio`.

RiftMap never changes qdisc itself. With `require_tc = true`, a live scan
refuses to run unless the root qdisc is TBF and its reported rate is at or
below the configured ceiling.

The `[budget]` section is only for estimates. `time_budget_secs` does not stop
a scan. Use `scan.max_runtime_secs` when the process needs a protective runtime
limit.

## Interpreting completion

Each scan writes `summary.json` before returning. Important fields:

- `completed`: all configured SYN rounds finished.
- `timed_out`: the protective `scan.max_runtime_secs` limit fired.
- `sent`: cumulative raw SYN packets sent.
- `open`, `closed`, `unreachable`, `no_response`: target state counts.
- `pcap_drops`: cumulative libpcap dropped packet count.
- `conflicting_observations`: targets that received lower-ranked duplicate or
  conflicting responses.
- `banner_queued`, `banner_done`, `banner_failed_or_incomplete`: banner
  pipeline progress.
- `interface_tx_packets`, `interface_tx_bytes`: Linux sysfs TX deltas observed
  across discovery and banner collection.

If `pcap_drops` is non-zero, treat the job as degraded. Open observations may
still be useful, but no-response results are not reliable negatives.

## Export behavior

`events.ndjson` is append-only and at-least-once. It may contain duplicate
records for the same target.

`export` writes `results.ndjson` by selecting the latest record for each
deterministic `result_id` and sorting results stably. By default, only open
targets are exported. With `output_all = true`, export also synthesizes closed,
unreachable, and no-response records from the state files.

Full export is refused when:

- The scan did not complete all SYN rounds.
- The job is degraded because pcap reported dropped packets.

## Troubleshooting

- `source port ... unavailable`: another local process is bound to
  `scan.source_port`; change the source port or stop that process.
- `root or CAP_NET_RAW/CAP_NET_ADMIN is required`: run as root or grant both
  capabilities to the binary.
- `root qdisc is not tbf`: run `tc-template`, review the output, and apply the
  TBF qdisc manually.
- `target set is empty after exclusions and safety policy`: every target was
  excluded or removed by reserved/private-address policy.
- `target count ... exceeds max_targets`: reduce inputs or raise
  `targets.max_targets` after confirming the scope is intentional.

Keep `.riftmap/jobs/<scan-id>` until `results.ndjson` has been reviewed and
archived according to your local data-handling policy.
