<!-- Thanks for contributing! Keep PRs focused and describe how you verified the change. -->

## Summary

<!-- What does this change and why? -->

## Changes

<!-- Bullet the key changes. -->

## Verification

<!-- How did you test it? e.g. `cargo test -p sl-node`, `npm --prefix sdk/typescript test`,
     a verify-*.sh script, or manual steps. Note KVM/root requirements if any. -->

## Checklist

- [ ] `cargo build --workspace` is warning-free (if Rust changed)
- [ ] Relevant tests added/updated and passing
- [ ] If the REST API changed: `contracts/openapi.yaml` ↔ SDK `ROUTES` ↔ SDK contract test kept in sync
- [ ] Docs updated if user-facing behavior changed
