# Sample Output

These examples show output shape only. Paths, scan IDs, counts, rates, and
timestamps vary by configuration and authorized lab.

## estimate

```text
targets: 2000
worst_packets: 6000
estimated_wire_bytes: 468000
syn_seconds: 0.0
banner_capacity_cps: 83.3
expected_open_targets: 20
banner_budget_capacity_open: 600000
banner_seconds: 0.2
estimated_total_seconds: 0.2
```

## doctor

```text
ok: source IPv4: 10.10.0.1
ok: interface: rift0
ok: source port 61000: available
ok: libpcap capture: ok
ok: tc root qdisc: verified
```

## scan

```text
job: .riftmap/jobs/2c5f4b8d9a01e392d88f4a22
summary: ScanSummary { completed: true, sent: 6000, syn_mss: Some(1460), open: 18, closed: 121, unreachable: 4, no_response: 1857, pcap_drops: 0, conflicting_observations: 0, interface_tx_packets: Some(6060), interface_tx_bytes: Some(510000), banner_queued: 18, banner_done: 18, banner_failed_or_incomplete: 0, timed_out: false }
```

## resume

```text
summary: ScanSummary { completed: true, sent: 6000, syn_mss: Some(1460), open: 18, closed: 121, unreachable: 4, no_response: 1857, pcap_drops: 0, conflicting_observations: 0, interface_tx_packets: Some(6060), interface_tx_bytes: Some(510000), banner_queued: 18, banner_done: 18, banner_failed_or_incomplete: 0, timed_out: false }
```

## report

```text
scan_id: 2c5f4b8d9a01e392d88f4a22
job_dir: .riftmap/jobs/2c5f4b8d9a01e392d88f4a22
target_count: 2000
round: 3
syn_attempts: 3
next_index: 2000
progress_percent: 100.00
summary: present
completed: true
timed_out: false
degraded: false
pcap_drops: 0
sent: 6000
state_open: 18
state_closed: 121
state_unreachable: 4
state_no_response: 1857
banner_queued: 18
banner_done: 18
banner_failed_or_incomplete: 0
next_action: export
protocol: ssh	12
protocol: smtp	6
banner_status: ok	18
software: ssh:OpenSSH_9.6	12
software: smtp:mail.example	6
```

## export

```text
exported: 18
output: .riftmap/jobs/2c5f4b8d9a01e392d88f4a22/results.ndjson
```

CSV export:

```text
exported: 18
output: .riftmap/jobs/2c5f4b8d9a01e392d88f4a22/results.csv
```

## validation-report

```json
{
  "schema_version": 1,
  "host": {
    "kernel": "Linux lab-host 6.8.0 ...",
    "cpu": "Intel(R) Xeon(R) ...",
    "memory_kb": 32899184,
    "libpcap": "1.10.4"
  },
  "network": {
    "interface": "rift0",
    "provider_egress_mbps": 10.0,
    "application_ratio": 0.8,
    "tc_ratio": 1.0
  },
  "targets": {
    "endpoint_count": 2000,
    "max_targets": 25000000
  },
  "job": {
    "size_bytes": 180224,
    "status": {
      "completed": true,
      "pcap_drops": 0
    }
  }
}
```
