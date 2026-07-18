# Validation

This document defines acceptance criteria for repeatable validation. It does
not authorize scanning any public network.

## Namespace Smoke Test

Run the smoke test only against isolated Linux network namespaces:

```sh
cargo build
sudo -E bash scripts/netns-smoke.sh target/debug/riftmap
```

Acceptance criteria:

- The script creates and tears down its namespace, veth, qdisc, target files,
  and job data without leaving public routes or live targets behind.
- `validate-config`, `estimate`, `doctor`, `scan --dry-run`, `scan`, `job
  status`, `resume`, `report`, and `export` complete successfully.
- `doctor` verifies raw-network privileges, libpcap access, source port
  availability, and the required TBF qdisc.
- `scan --dry-run` prints a deterministic `order_digest` for the materialized
  target set.
- The live scan observes the namespace services expected by the script and does
  not scan outside the reserved local namespace addresses.
- `summary.json` has `completed = true`, `timed_out = false`, and
  `pcap_drops = 0`.
- `results.ndjson` is stable after repeated `export` runs.
- `report` includes protocol and banner status counts for the observed open
  services.
- A repeated `resume` on a completed job is idempotent and does not duplicate
  completed banner work.

## Native Linux Scale Report

Before calling a build production-ready, record a validation report from an
authorized lab or owned network. Include:

- Host kernel, CPU, memory, NIC, driver, MTU, offload settings, and libpcap
  version.
- Provider or lab egress ceiling, configured `provider_egress_mbps`,
  `application_ratio`, `tc_ratio`, and actual `tc -s -j qdisc` output before
  and after the scan.
- Target count, shard settings, protocol, port, SYN attempts, banner timeouts,
  banner concurrency, and banner CPS.
- `estimate` output captured before the scan.
- `doctor` output captured immediately before the scan.
- Peak resident memory and job directory size.
- `summary.json`, `job status --json`, and `report --json`.
- `validation-report -c <config> --job <job>` output.
- Interface TX packet and byte deltas compared with `summary.json`.
- libpcap drop counters and any degraded status.
- Export row counts for default export and, when safe, `output_all = true`.
- Any observed discrepancy between expected services and exported open,
  closed, unreachable, or no-response states.

Native acceptance criteria:

- Traffic remains under the configured application budget and externally
  enforced hard ceiling.
- `pcap_drops` remains zero for scans where no-response results are treated as
  reliable negatives.
- Resume from interruption preserves progress and produces the same final
  export as an uninterrupted run over the same authorized target set.
- Memory and job data growth remain within the operator's documented limits at
  the tested target count.

Use the built-in report collector after a scan:

```sh
riftmap validation-report -c config.local.toml --job .riftmap/jobs/<scan-id> \
  > native-validation-report.json
```

The report is evidence packaging only. It does not replace the operator's
obligation to run the scan in an authorized environment and review provider,
legal, and local safety constraints.

For a full evidence bundle, use the native lab harness:

```sh
cargo build --release
RIFTMAP_LAB_EXPECT_ENDPOINTS=20000000 \
RIFTMAP_LAB_SKIP_DOCTOR=1 \
  scripts/native-lab-validation.sh target/release/riftmap config.local.toml \
  validation/native-20m-dry-run
```

The default harness path runs offline validation and `scan --dry-run`, capturing
`/usr/bin/time -v` output and materialized job size. This is the required path
for 20-million-endpoint resident-memory evidence when live traffic is not
authorized. `RIFTMAP_LAB_SKIP_DOCTOR=1` is acceptable only for offline dry-run
materialization evidence where raw-network privileges are intentionally not
used.

For authorized live validation:

```sh
RIFTMAP_LAB_RUN_LIVE=1 \
  scripts/native-lab-validation.sh target/release/riftmap config.local.toml \
  validation/native-live
```

Live mode also captures `doctor`, qdisc counters before and after the scan,
`job status --json`, `report --json`, `export`, `validation-report`, interface
counters, and job size.
