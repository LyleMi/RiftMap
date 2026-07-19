# Known limitations

The repository is being published as a development handoff. The MVP feature set
is implemented, but production use still needs broader native-Linux proof:

- The Linux backend has unit coverage and a namespace-isolated CI smoke test,
  but tc accuracy, loss curves, and 20-million-target RSS still require broader
  native-Linux validation.
- Each job supports one or more IPv4 TCP service endpoints, but every endpoint
  still uses passive, server-first banner collection.
- Shards are created and run explicitly. Cross-host scheduling, coordination,
  and result merging are not implemented.
- IPv6, UDP, TLS handshakes, authentication, active probes, and vulnerability
  detection are outside the current safety and traffic model.

Do not use the current raw scanner against external networks. Continue
development with namespace-isolated synthetic services and explicitly
authorized final acceptance targets.

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the fuller backlog.
