# Safety model

RiftMap is built to reduce accidental scope expansion, but it does not decide
whether a scan is legal, authorized, or acceptable to a provider. Operators are
responsible for target authorization and local policy.

## Target filtering

Target inputs accept IPv4 addresses and CIDRs. Blank lines, whole-line
comments, and inline `#` comments are ignored. Excludes always win.

For CIDR inputs with prefixes `/0` through `/30`, the subnet-directed broadcast
address is removed automatically. Explicit single-IP entries and `/31` or `/32`
entries are preserved before the broader safety filter is applied.

The following categories are always removed:

- Unspecified addresses.
- Loopback addresses.
- Link-local addresses.
- Shared address space.
- Documentation and benchmarking ranges.
- Multicast, reserved, and limited broadcast space.

RFC1918 private ranges are removed unless `allow_private = true`.

## Fixture ranges

Files under `fixtures/` are documentation examples. They are not live scan
targets. The reserved documentation networks used there are always removed by
the target safety policy before a job is created.

## Traffic model

Raw discovery sends TCP SYN packets only. Banner collection uses ordinary kernel
TCP connections and waits for passive, server-first banners for the configured
protocol. RiftMap does not send client protocol data, authentication material,
exploit payloads, or vulnerability checks.

Current protocol support is intentionally narrow: SSH, FTP, MySQL, SMTP, Redis,
and Postgres. Redis and Postgres usually do not emit a useful server-first
banner, so RiftMap only parses unsolicited server data when present. IPv6, UDP,
TLS handshakes, active application probes, authentication, and vulnerability
detection are outside the current implementation.

## Negative results

Open observations are cookie-validated SYN-ACKs. Closed and unreachable
observations come from validated TCP RST or ICMP replies.

No-response is weaker. It means RiftMap did not observe a validated response
after the configured SYN attempts. It is not proof that a host or service does
not exist.

When pcap reports dropped packets, the job is degraded. Degraded jobs can still
contain useful positive observations, but no-response results are not reliable.
For that reason, `output_all = true` export is refused for degraded jobs.

## Rate safety

Application pacing and operator-applied `tc` ceilings are separate controls.
Use both for live scanning:

- Keep `application_ratio` below `tc_ratio`.
- Use `tc-template` to generate a qdisc command, then review and apply it
  manually.
- Keep `require_tc = true` unless a separate external hard ceiling is already
  in place.

Run `doctor` immediately before a live scan. It checks source address
selection, source-port availability, Linux capabilities, libpcap access, and
the qdisc requirement when enabled.
