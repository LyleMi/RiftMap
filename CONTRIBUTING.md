# Contributing

RiftMap handles raw network traffic. Keep development and automated tests
offline or inside isolated network namespaces, and never add public addresses
to tests, examples, or fixtures.

## Development setup

Use Rust 1.85. Linux builds need `pkg-config` and the libpcap development
headers. The live scanner additionally needs `iproute2` and raw-network
privileges; normal unit tests do not.

```sh
sudo apt-get install build-essential pkg-config libpcap-dev iproute2
cargo build --locked
```

Copy `config.example.toml` to the ignored `config.local.toml` for local work.
Do not commit target lists, captures, keys, logs, or `.riftmap/` job data.

## Before opening a pull request

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
```

When Linux packet handling or the end-to-end job pipeline changes, also run:

```sh
cargo build
sudo -E bash scripts/netns-smoke.sh target/debug/riftmap
```

Add focused unit tests beside changed code. Integration tests must use network
namespaces or an explicitly authorized private lab. Explain scanning and safety
impact in the pull request, even when the answer is `None`.

Commits follow Conventional Commits, for example
`fix(scanner): preserve retry accounting`. Keep each commit to one coherent
change.

## Releases

Maintainers release from a clean, reviewed commit by updating the version in
`Cargo.toml`, merging through CI, and pushing a matching annotated tag such as
`v0.2.0`. The release workflow rejects a tag whose version differs from the
crate version. See [`docs/CI_CD.md`](docs/CI_CD.md) for the full process.
