# Contributing

## Local checks

Use Rust 1.85 or newer. Repository builds use the committed lockfile.

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo test --locked --doc
python3 scripts/check_vectors.py
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps
cargo run --locked --example schnorr_example
cargo run --locked --example pedersen_example
cargo run --locked --example ring_example
cargo package --locked
```

For packaging an uncommitted working tree, use `cargo package --locked --allow-dirty`.
This creates and verifies a local archive; it does not publish to crates.io.

The independent vector check uses Python 3 and its standard library; it does not
require a virtual environment or additional packages.

## Changes to protocols

Explain the statement being proven, the witness, the assumptions, and the
verification equation. Include primary references, transcript domains and field
ordering, byte layouts, and negative tests for changed statements and malformed
inputs. Add a runnable example that does not disclose secret state.

Treat transcript changes as format changes. Update docs/PROTOCOLS.md,
CHANGELOG.md, and deterministic vectors together. Never preserve compatibility
by silently accepting noncanonical encodings or prover-selected challenges.

Use deterministic RNGs only in tests. Keep zeroization and redaction for secret
state, and do not add `Clone` or public scalar fields to nonce/key types.

## Release checklist

1. Run the local checks and confirm the GitHub Actions jobs are green.
2. Review the API and wire-format changes and update the changelog.
3. Confirm the release remains explicitly educational and unaudited.
4. Set the intended version and release notes after maintainer review.
5. Publish or tag only with the maintainer's explicit approval.

No release or crate publication is performed automatically by CI.
