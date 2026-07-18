# Roadmap

This file tracks product and validation gaps that are visible from the current
MVP. It is not a release commitment.

## Production readiness

- Validate tc accuracy across common NICs, virtual interfaces, and cloud
  environments.
- Measure loss curves at realistic target counts and provider rates.
- Reproduce 20-million-target resident memory behavior on native Linux.
- Add documented acceptance criteria for the namespace smoke test and any
  larger authorized lab tests.

## Operator experience

- Completed: `job status` reads `checkpoint.json` and optional `summary.json`.
- Completed: `job list` summarizes the configured job root.
- Completed: `validate-config` performs target-count and path checks without
  raw-network privileges.
- Add export filters such as state, protocol, and banner status.
- Add CSV output for simple inventory ingestion.

## Scan capabilities

- Support multiple ports per run while preserving deterministic ordering and
  resumability.
- Implement explicit sharding. `checkpoint.json` already has `shard_index` and
  `shard_count`, but job creation currently fixes them to `0/1`.
- Consider additional passive banner parsers such as SMTP, Redis, Postgres, and
  TLS certificate collection if the traffic model is expanded.
- Keep active probes, authentication, and vulnerability detection separate from
  the current passive inventory scope unless the safety model is redesigned.

## Data model

- Publish a versioned JSON Schema for `results.ndjson` and `summary.json`.
- Add compatibility tests for old job directories.
- Decide whether `checkpoint.json` should remain internal-only or become a
  documented operational API.

## Documentation

- Keep English and Chinese READMEs aligned.
- Add sample command output for `estimate`, `doctor`, `scan`, `resume`, and
  `export`.
- Add a native-Linux validation report once broader proof is complete.
