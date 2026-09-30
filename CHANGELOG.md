# Changelog

## 0.2.0 — Unreleased

### Added

- Pedersen commitments with opening verification and homomorphic addition.
- Context-bound Fiat-Shamir proofs of Pedersen opening knowledge.
- Unlinkable Schnorr OR ring signatures over ordered, validated rings.
- Non-interactive Schnorr proofs with context-bound SHA-512 challenges.
- Canonical public encodings and explicit validation errors.
- Three runnable examples, protocol documentation, adversarial tests, and CI.

### Changed

**Breaking change:** the original toy `u64` API is replaced by Ristretto255.

The old modulus was `p = 2^61 - 1` with generator `g = 2`. Since
`2^61 = 1 mod p` and 61 is prime, that generator has order 61. The old public
key therefore depended on only 61 possible exponents. It was not a suitable
cryptographic group and its keys and transcripts must not be carried forward.

- `SchnorrParams` and public-field `SchnorrKeypair` are removed.
- Use `SecretKey::generate(&mut OsRng)` and `secret.public_key()` for keys.
- Replace `SchnorrProof::create_commitment` with `SchnorrCommitment::new`.
- Replace `create_response` with the state-consuming `respond` method.
- Verify interactive responses with the verifier's retained commitment and
  `SchnorrChallenge`; a proof no longer supplies its own interactive challenge.
- Use `SchnorrProof::prove` / `verify` for non-interactive proofs.
- Verification returns `Result<(), Error>` instead of `bool`.
- RNG arguments require `RngCore + CryptoRng`; `OsRng` is re-exported.
- Secret state is private, debug-redacted, and zeroized on drop.
- Cargo metadata uses valid categories, declares Rust 1.85, and commits a lockfile.

The 0.2 formats are crate-specific and incompatible with the old transcripts.
Do not reinterpret old integer keys as new Ristretto keys; generate fresh keys.

## 0.1.0

- Initial educational Schnorr demonstration using modular integer arithmetic.
