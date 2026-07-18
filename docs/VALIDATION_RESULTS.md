# Validation Results

This file records validation evidence produced from this repository state. It
does not authorize scanning public networks.

## Namespace Smoke

Command:

```sh
sudo -n -E bash scripts/netns-smoke.sh target/debug/riftmap
```

Result: passed on Linux `6.8.0-117-generic`.

Coverage:

- Multi-service endpoint materialization.
- TBF qdisc verification on an isolated veth interface.
- `estimate`, `doctor`, `scan --dry-run`, live `scan`, `job status`,
  `job status --json`, `resume`, `report`, `report --json`,
  `validation-report`, and repeated `export`.
- Completed scan with `pcap_drops = 0`.
- Stable export containing one open SSH endpoint and one no-response endpoint
  inside the isolated namespace.

## 20M Endpoint Dry-Run

Command:

```sh
RIFTMAP_LAB_EXPECT_ENDPOINTS=20971518 RIFTMAP_LAB_SKIP_DOCTOR=1 \
  bash scripts/native-lab-validation.sh target/debug/riftmap \
  /tmp/riftmap-20m-validation-1784380365-804782/config/config.toml \
  /tmp/riftmap-20m-validation-1784380365-804782/artifacts-skip-doctor
```

Target input:

```text
10.0.0.0/8
172.16.0.0/10
```

Configuration:

- `allow_private = true`
- `max_targets = 25000000`
- one SSH service endpoint
- dry-run only; no live packets transmitted

Observed evidence:

- `target_count`: `20971518`
- `order_digest`:
  `5d1e34e75b7eed0872e8a91a0c51d764d45b568a0a098ec323e35a9af317ef0b`
- `/usr/bin/time -v` maximum resident set size: `154496` KB
- elapsed time: `5:01.40`
- socket messages sent: `0`
- socket messages received: `0`
- apparent job directory size: `440402868` bytes
- exit status: `0`

Interpretation:

This reproduces 20-million-endpoint job materialization and deterministic
dry-run ordering on native Linux without live traffic. It is evidence for
resident memory behavior of the offline materialization path. It is not a
substitute for authorized live loss-curve or provider-rate validation.

## Remaining External Evidence

The following still require authorized lab or provider environments not
represented by the isolated namespace or dry-run run above:

- tc accuracy across multiple common NICs, virtual interfaces, and cloud
  environments.
- loss curves at realistic live target counts and provider rates.
- production-like live validation report from an owned or explicitly
  authorized target set.
