# Repository Guidelines

## Project Structure & Module Organization

RiftMap is a Rust 2024 crate with both a reusable library and the `riftmap` CLI. `src/lib.rs` exposes the core modules; `src/main.rs` parses commands. Domain logic is split by responsibility: target parsing in `src/target.rs`, packet handling in `src/packet.rs`, scan orchestration in `src/scanner.rs`, job persistence in `src/job.rs`, and protocol banner parsing in `src/protocol.rs`. Unit tests live beside their modules under `#[cfg(test)]`. Example target lists are in `fixtures/`; configuration starts from `config.example.toml`. CI is defined in `.github/workflows/ci.yml`.

## Build, Test, and Development Commands

- `cargo build --release` builds the optimized CLI (Linux needs `libpcap-dev` and `pkg-config`).
- `cargo run -- estimate -c config.local.toml` validates inputs and estimates scan cost without transmitting packets.
- `cargo run -- scan -c config.local.toml --dry-run` prepares a job and verifies deterministic ordering safely.
- `cargo fmt --all -- --check` checks standard Rust formatting.
- `cargo clippy --all-targets -- -D warnings` rejects lint warnings.
- `cargo test --all-targets` runs the full test suite.

Use Rust 1.85, the repository MSRV and CI toolchain. Live scanning is Linux-only and requires raw-network capabilities; offline commands and most tests are portable.

## Coding Style & Naming Conventions

Follow `rustfmt` defaults (four-space indentation). Use `snake_case` for modules, functions, and variables; `PascalCase` for types and traits; and `SCREAMING_SNAKE_CASE` for constants. Keep modules focused and propagate errors with `anyhow` or typed `thiserror` errors. Unsafe operations are denied unless explicitly contained in an `unsafe` block.

## Testing Guidelines

Add focused unit tests next to changed logic and use descriptive `snake_case` test names. Property-based cases may use `proptest`; filesystem tests should use `tempfile`. Integration tests must run in network namespaces or reserved local lab ranges. Never let tests or examples scan public addresses.

## Commit & Pull Request Guidelines

Commit messages must follow the Conventional Commits specification, using short, imperative descriptions such as `fix(ci): support Rust 1.85`. Keep each commit scoped to one coherent change. Pull requests should explain behavior and safety impact, list validation commands, link relevant issues, and include sample CLI output when user-visible behavior changes. Ensure formatting, Clippy, tests, and both CI compile targets pass.

## Security & Configuration

Copy `config.example.toml` to ignored `config.local.toml`; never commit real targets, captures, keys, logs, or `.riftmap/` job data. Scan only explicitly authorized networks, and review `KNOWN_LIMITATIONS.md` before native testing.
