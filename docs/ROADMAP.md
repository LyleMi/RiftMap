# Roadmap

This file tracks product and validation gaps that are visible from the current
MVP. It is not a release commitment.

## Production readiness

- Validate tc accuracy across common NICs, virtual interfaces, and cloud
  environments.
- Measure loss curves at realistic target counts and provider rates.
- Completed: reproduce 20-million-endpoint dry-run resident memory behavior on
  native Linux and record evidence in `docs/VALIDATION_RESULTS.md`.
- Completed: add `validation-report` to collect native/lab evidence into a
  structured JSON artifact.
- Completed: add `scripts/native-lab-validation.sh` to collect tc, loss, dry-run
  RSS, job size, live status/report/export, and validation-report artifacts in
  authorized native labs.
- Completed: add documented acceptance criteria for the namespace smoke test
  and larger authorized lab tests in `docs/VALIDATION.md`.

## Operator experience

- Completed: `job status` reads `checkpoint.json` and optional `summary.json`.
- Completed: `job list` summarizes the configured job root.
- Completed: `validate-config` performs target-count and path checks without
  raw-network privileges.
- Completed: export filters by state, protocol, and banner status.
- Completed: CSV output for simple inventory ingestion.
- Completed: `job status --json` and `job list --json` for automation.
- Completed: `report` summarizes status, protocol, banner status, and software
  distributions.
- Completed: `job prune` removes old job directories from the configured job
  root with dry-run support.

## Scan capabilities

- Completed: support multiple ports per run with deterministic endpoint
  ordering and resumability.
- Completed: explicit sharding with `scan --shard-index` and `--shard-count`.
- Completed: add passive SMTP, Redis, and Postgres parsers. TLS certificate
  collection remains out of scope unless the traffic model is expanded.
- Completed: keep active probes, authentication, and vulnerability detection
  separate from the passive inventory scope.

## Data model

- Completed: publish versioned JSON Schemas for `results.ndjson` and
  `summary.json` under `schemas/`.
- Completed: add compatibility tests for old result, summary, checkpoint, and
  banner-state behavior.
- Completed: keep `checkpoint.json` internal-only; stable operational surfaces
  are `job status --json`, `job list --json`, `report --json`, `summary.json`,
  and exported results.

## Documentation

- Completed: keep English and Chinese READMEs aligned for current commands and
  safety scope.
- Completed: add sample command output for `estimate`, `doctor`, `scan`,
  `resume`, `report`, and `export` in `docs/SAMPLE_OUTPUT.md`.
- Completed: document namespace smoke acceptance criteria and native Linux
  validation report requirements in `docs/VALIDATION.md`.
- Add a native-Linux validation report once broader proof is complete.
