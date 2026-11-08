## Summary

Describe the behavior change and why it is needed.

## Safety impact

Describe any effect on target filtering, packet transmission, rate limits,
privileges, persistence, or negative-result interpretation. Write `None` when
the change cannot affect live scanning.

## Validation

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --locked --all-targets -- -D warnings`
- [ ] `cargo test --locked --all-targets`
- [ ] Namespace smoke test run when Linux packet handling changed
- [ ] Documentation and sample output updated when user-visible behavior changed

## Related issues

Link related issues or write `None`.
