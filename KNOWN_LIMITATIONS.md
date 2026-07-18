# Known limitations

The repository is being published as a development handoff. The MVP feature set
is implemented, but production use still needs broader native-Linux proof:

- The Linux backend has unit coverage and a namespace-isolated CI smoke test,
  but tc accuracy, loss curves, and 20-million-target RSS still require broader
  native-Linux validation.

Do not use the current raw scanner against external networks. Continue
development with namespace-isolated synthetic services and explicitly
authorized final acceptance targets.
