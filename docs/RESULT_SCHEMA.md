# Result schema

RiftMap writes newline-delimited JSON under each job directory. The schema is
append-friendly and intended for downstream inventory pipelines.

## Files

- `events.ndjson`: append-only observations. This file is at-least-once and may
  contain duplicate `result_id` records.
- `results.ndjson`: deterministic export output. This file is rewritten by
  `riftmap export`.
- `summary.json`: scan-level counters and completion status.
- `checkpoint.json`: resumable job metadata. It is internal state, not a stable
  reporting API.

## Result records

Each line in `events.ndjson` and `results.ndjson` is a `ResultV1` object. The
versioned JSON Schema is published at
[`schemas/result-v1.json`](../schemas/result-v1.json).

Common fields:

- `schema_version`: currently `1`.
- `result_id`: BLAKE3-derived stable ID for `scan_id`, target IP, and port.
- `scan_id`: job ID.
- `ip`: target IPv4 address.
- `port`: scanned TCP port.
- `protocol`: configured protocol, one of `ssh`, `ftp`, `mysql`, `smtp`,
  `redis`, or `postgres`.
- `state`: one of `open`, `closed`, `unreachable`, or `no_response`.
- `syn_attempts`: SYN attempt number where the state was observed. Synthesized
  no-response records use the configured maximum.
- `rtt_ms`: observed response RTT in milliseconds when available.
- `conflicting_observations`: duplicate or lower-ranked observations seen for
  the same target.
- `first_observed_at`, `last_observed_at`: Unix epoch milliseconds as strings
  for banner observations. Synthesized records leave these null.

Banner fields:

- `banner_status`: one of `ok`, `connect_failed`, `timeout`,
  `protocol_mismatch`, or `oversized`.
- `banner_base64`: raw captured banner bytes encoded as base64 when present.
- `banner_text`: parsed text for text protocols when available.
- `ssh`: SSH-specific parsed fields.
- `ftp`: FTP-specific parsed fields.
- `mysql`: MySQL-specific parsed fields.
- `smtp`: SMTP-specific parsed fields.
- `redis`: Redis RESP-specific parsed fields for unsolicited responses.
- `postgres`: PostgreSQL backend-message parsed fields for unsolicited
  responses.

Example open SSH result:

```json
{"schema_version":1,"result_id":"...","scan_id":"...","ip":"10.0.0.10","port":22,"protocol":"ssh","state":"open","syn_attempts":1,"rtt_ms":12.5,"conflicting_observations":0,"first_observed_at":"1720000000000","last_observed_at":"1720000000000","banner_status":"ok","banner_base64":"U1NILTIuMC1PcGVuU1NIXzkuNg0K","banner_text":"SSH-2.0-OpenSSH_9.6","ssh":{"protocol_version":"2.0","software_version":"OpenSSH_9.6","comments":null},"ftp":null,"mysql":null}
```

## Summary fields

`summary.json` contains the scan-level counters described below. The versioned
JSON Schema is published at
[`schemas/summary-v1.json`](../schemas/summary-v1.json).

When `[scan].services` contains multiple entries, target counts and state
counters are endpoint counts: one target IP multiplied by one configured
service port/protocol.

- `completed`: true when all SYN rounds finished.
- `sent`: cumulative raw SYN packets sent.
- `syn_mss`: MSS advertised in raw SYN packets on Linux.
- `open`, `closed`, `unreachable`, `no_response`: state counters.
- `pcap_drops`: cumulative libpcap dropped packet count.
- `conflicting_observations`: total duplicate or lower-ranked observations.
- `interface_tx_packets`, `interface_tx_bytes`: Linux interface TX deltas.
- `banner_queued`, `banner_done`, `banner_failed_or_incomplete`: banner
  pipeline counters.
- `timed_out`: true when `scan.max_runtime_secs` stopped the scan.

## Export guarantees

`results.ndjson` and `results.csv` are stable for a given job state. Export
deduplicates by `result_id`, sorts by `result_id`, and writes one row per
selected result.

Default export includes only open targets. When `output_all = true`, export
includes synthesized records for targets without events, but only after all SYN
rounds completed and only when pcap drops are zero.

CLI filters can select by `--state`, `--protocol`, and `--banner-status`.
`--format csv` writes `results.csv`; nested protocol-specific fields are encoded
as JSON strings inside CSV cells so inventory tools can ingest core columns
without losing detailed fields.
