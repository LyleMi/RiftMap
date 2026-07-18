# Known limitations

The repository is being published as a development handoff. Before production
use, the following plan items still need implementation or native-Linux proof:

- The Linux backend has passed a manual x86_64 Linux 6.8 netns/veth runtime
  test, including Ctrl+C/resume, but still lacks automated native integration
  coverage.
- SYN transmission currently uses one raw-socket send per packet, not
  `sendmmsg` batching; route-MTU-derived MSS is not implemented.
- Target files must explicitly exclude subnet-directed broadcast addresses;
  a raw send to such an address currently aborts the scan with `EACCES`.
- Banner traffic is CPS/concurrency limited but is not yet charged to the
  shared estimated-wire token bucket.
- Per-response RTT, exact attempt counts, conflicting observation history, and
  interface TX telemetry are incomplete.
- The pcap decoder supports Ethernet and raw IPv4 framing; Linux cooked capture
  link-layer headers need explicit handling and tests.
- Netns/veth/tc accuracy, loss curves, 20-million-target RSS, and aarch64
  compilation still require CI or broader native-Linux validation.

Do not use the current raw scanner against external networks. Continue
development with namespace-isolated synthetic services and explicitly
authorized final acceptance targets.
