# Known limitations

The repository is being published as a development handoff. The MVP feature set
is implemented, but production use still needs broader native-Linux proof:

- The Linux backend has unit coverage and a namespace-isolated CI smoke test,
  but tc accuracy, loss curves, and 20-million-target RSS still require broader
  native-Linux validation.
- Each job supports one IPv4 TCP port and one passive banner protocol.
- Distributed sharding is not implemented. Job metadata contains shard fields,
  but job creation currently fixes them to a single shard.
- IPv6, UDP, TLS handshakes, authentication, non-SSH active probes, and
  vulnerability detection are outside the current safety and traffic model.
  SSH `version_exchange` and `kexinit_probe` are available only as explicit
  active probe modes; the default remains passive banner collection.

Do not use the current raw scanner against external networks. Continue
development with namespace-isolated synthetic services and explicitly
authorized final acceptance targets.

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the fuller backlog.
