# CI/CD

GitHub Actions validates changes and packages tagged releases. No workflow is
allowed to scan public addresses or deploy the scanner to a host.

## Continuous integration

`.github/workflows/ci.yml` deliberately splits checks to limit hosted-runner
usage:

- Pull requests run only `test`, which checks formatting and Clippy and runs all
  tests with Rust 1.85.
- Pushes to `main` run `aarch64-check` and `native-netns-smoke` once after the
  change is merged. The first checks the Linux aarch64 target; the second
  exercises the scan pipeline in isolated Linux network namespaces.
- Manual dispatch runs all three jobs when a maintainer needs a full rerun.

Pushes to non-default branches do not trigger a second CI run in addition to
the pull-request run. Release builds happen only in the tag-triggered release
workflow.

All Cargo commands use `Cargo.lock`. Jobs have explicit timeouts, read-only
repository permissions, and dependency caches. A newer run on the same branch
cancels an obsolete CI run.

Recommended branch protection for the default branch:

1. Require a pull request. A solo-maintainer repository can require zero
   approvals; raise this to one approval when another maintainer is available.
2. Require the pull-request `test` job to pass. The post-merge aarch64 and
   namespace jobs remain visible on `main` without consuming two runners for
   every pull-request revision.
3. Require the branch to be current before merging.
4. Block force pushes and branch deletion.
5. Restrict direct pushes to maintainers or disallow them entirely.

These repository settings must be enabled in GitHub; workflow files cannot
enforce them by themselves.

For the current GitHub repository, Actions has read-only default permissions,
cannot approve pull requests, and retains workflow logs and artifacts for seven
days. The release workflow requests `contents: write` explicitly and only for
tagged releases.

## Tagged releases

`.github/workflows/release.yml` runs for semantic version tags such as `v0.2.0`
and can also be manually dispatched for an existing tag. It:

1. verifies that the tag exists and matches the package version in
   `Cargo.toml`;
2. builds the locked dependency graph with Rust 1.85;
3. packages the x86_64 Linux GNU binary, READMEs, and licenses;
4. writes `SHA256SUMS`; and
5. creates a GitHub Release with generated notes.

The workflow has `contents: write` only because creating a release requires it.
It does not publish to crates.io and does not create or move tags.

Release checklist:

```sh
# Update Cargo.toml, then refresh the lockfile.
cargo check
cargo test --locked --all-targets
git tag -a v0.2.0 -m "v0.2.0"
git push origin v0.2.0
```

If a release job fails, fix the underlying commit and publish a new version.
Do not move an already published version tag.

## Dependency updates

`.github/dependabot.yml` opens grouped monthly updates for Cargo dependencies
and GitHub Actions. Treat those pull requests like any other change: review the
changelog, keep `Cargo.lock` committed, and require the full CI suite.
