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
target/release/riftmap validate-config -c config.local.toml
target/release/riftmap estimate -c config.local.toml
target/release/riftmap tc-template -c config.local.toml
# Review and apply the printed tc command yourself.
sudo target/release/riftmap doctor -c config.local.toml
sudo target/release/riftmap scan -c config.local.toml --dry-run
sudo target/release/riftmap scan -c config.local.toml
sudo target/release/riftmap scan -c config.local.toml --shard-index 0 --shard-count 4
target/release/riftmap job status --job .riftmap/jobs/<scan-id>
target/release/riftmap job status --job .riftmap/jobs/<scan-id> --json
target/release/riftmap report --job .riftmap/jobs/<scan-id>
target/release/riftmap validation-report -c config.local.toml --job .riftmap/jobs/<scan-id>
target/release/riftmap export --job .riftmap/jobs/<scan-id>
target/release/riftmap export --job .riftmap/jobs/<scan-id> --state open --banner-status ok --format csv
target/release/riftmap job prune -c config.local.toml --older-than-days 30 --dry-run
```

Use `resume` after Ctrl-C, timeout, or process failure:

```sh
sudo target/release/riftmap resume --job .riftmap/jobs/<scan-id>
```

The job stores an immutable `config.toml`, so resume and export use the
configuration captured when the job was created.

For multi-port inventory, set `[scan].services` in the config. Each target IP is
materialized once per `{ port, protocol }` service endpoint, and `max_targets`
is enforced against endpoint count rather than unique IP count.

## Offline checks

Use `validate-config` before any privileged preflight or live scan:

```sh
target/release/riftmap validate-config -c config.local.toml
```

This command loads TOML, resolves target and job-root paths relative to the
config file, parses include and exclude files, applies the private/reserved
address policy, verifies the filtered target count is non-zero and within
`targets.max_targets`, and prints the same key estimate fields as `estimate`.
It does not open pcap, check root or capabilities, inspect qdisc, or call `tc`.

To discover jobs under the configured `output.job_root`:

```sh
target/release/riftmap job list -c config.local.toml
```

Each job is one tab-separated line:

```text
scan_id  status  targets  round  next_index  completed  degraded  updated_at  path
```

`updated_at` is the `checkpoint.json` modification time as Unix seconds, or
`unknown` if unavailable. A missing job root prints no rows and exits
successfully. A malformed job prints `invalid` for its status without failing
the whole list.

To inspect one job without raw-network privileges:

```sh
target/release/riftmap job status --job .riftmap/jobs/<scan-id>
```

`job status` reads `checkpoint.json`, the immutable job `config.toml`, and
`summary.json` when present. If `summary.json` is missing, it prints
`summary: missing`, falls back to state files for counters, and suggests
`next_action: inspect_missing_summary`.

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

`[budget].time_budget_secs` is only an estimate unless
`enforce_time_budget = true`. When enforcement is enabled, RiftMap uses the
smaller of `budget.time_budget_secs` and `scan.max_runtime_secs` as the
protective scan timeout.

Use `report` for a compact status and inventory summary. It includes the same
job status counters plus protocol, banner status, and software distributions
from `events.ndjson`; add `--json` for automation.

## Export behavior

`events.ndjson` is append-only and at-least-once. It may contain duplicate
records for the same target.

`export` writes `results.ndjson` or `results.csv` by selecting the latest record
for each deterministic `result_id` and sorting results stably. By default, only
open targets are exported. Use `--state`, `--protocol`, and `--banner-status`
to filter selected rows. With `output_all = true`, export also synthesizes
closed, unreachable, and no-response records from the state files.

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

Use `job prune` only after exports have been archived. `--dry-run` prints
candidate job directories without deleting them; without `--dry-run`, only
directories under the configured job root that contain `checkpoint.json` are
removed.
