# Zero-Knowledge Proofs

A small Rust library for studying proofs of knowledge and commitments over
**Ristretto255**, with complete examples and tests.

**Educational and unaudited.** This project is not a production cryptography
library. Read [SECURITY.md](https://github.com/echostacc/zk-proofs/blob/main/SECURITY.md) before experimenting with it.

## Implemented protocols

| Protocol | What it demonstrates | Example |
| --- | --- | --- |
| Interactive Schnorr | Knowledge of a secret key, with a verifier-issued challenge | `schnorr_example` |
| Fiat-Shamir Schnorr | A non-interactive proof bound to a public key and context | `schnorr_example` |
| Pedersen commitments | Hiding a scalar, opening it, and adding commitments | `pedersen_example` |
| Pedersen opening proof | Knowledge of a value and blinding without disclosing them | `pedersen_example` |
| Ring signatures | A message signed by one member of an ordered ring | `ring_example` |

A commitment is a building block, not a zero-knowledge proof by itself. The ring
signature is an unlinkable Schnorr OR proof: it has no key images or double-spend
detection. Groth16, PLONK, Bulletproofs, and STARKs are **not implemented**.

## Run it

Requires **Rust 1.85 or newer**.

```sh
git clone https://github.com/echostacc/zk-proofs.git
cd zk-proofs
cargo test --locked
cargo run --locked --example schnorr_example
cargo run --locked --example pedersen_example
cargo run --locked --example ring_example
cargo doc --locked --no-deps --open
```

The examples check successful verification and rejection of changed inputs.
They never print secret keys, nonces, or Pedersen openings.

For a local dependency, add this to another project's `Cargo.toml`:

```toml
[dependencies]
zk-proofs = { path = "../zk-proofs" }
```

Version 0.2.0 in this repository is not a claim of publication on crates.io.

## Schnorr: prove knowledge of a key

Let `G` be the fixed Ristretto generator, `x` a secret scalar, and `P = xG` the
public key. The prover samples a fresh nonce `r`, sends `R = rG`, and answers a
challenge `c` with `z = r + cx`. The verifier checks `zG = R + cP`.
Scalar arithmetic is modulo the prime group order.

In the interactive protocol, the verifier samples `c` **after** receiving `R`
and verifies using the commitment and challenge it retained:

```rust
use zk_proofs::{OsRng, SecretKey, SchnorrChallenge, SchnorrCommitment};

let mut rng = OsRng;
let secret = SecretKey::generate(&mut rng);
let public = secret.public_key();

let prover = SchnorrCommitment::new(&secret, &mut rng);
let expected_commitment = prover.commitment();
let expected_challenge = SchnorrChallenge::generate(&mut rng);
let response = prover.respond(&expected_challenge); // Consumes nonce state.
response.verify(&public, expected_commitment, &expected_challenge)?;
# Ok::<(), zk_proofs::Error>(())
```

An arbitrary saved interactive transcript is not a standalone proof of
knowledge: anyone can simulate one by choosing the challenge themselves.
For non-interactive proofs, Fiat-Shamir derives the challenge by hashing the
public key, commitment, fixed generator, and application context:

```rust
use zk_proofs::{OsRng, SecretKey, SchnorrProof};

let secret = SecretKey::generate(&mut OsRng);
let public = secret.public_key();
let context = b"my-app/login/session-123";
let proof = SchnorrProof::prove(&secret, context, &mut OsRng);
let received = SchnorrProof::from_bytes(&proof.to_bytes())?;
received.verify(&public, context)?;
assert!(received.verify(&public, b"other-session").is_err());
# Ok::<(), zk_proofs::Error>(())
```

The verifier supplies the expected context. Include a fresh session identifier
when replay prevention matters. These formats are specific to this crate;
they are not Bitcoin BIP-340 signatures.

## Pedersen: commit, combine, and prove an opening

A commitment is `C = vG + bH`, where `v` is a value, `b` is a fresh random
blinding scalar, and `H` is a second generator derived from a fixed hash-to-point
domain. No known scalar relationship between `G` and `H` is selected.

```rust
use zk_proofs::{OsRng, PedersenCommitment, PedersenProof};

let (a, a_opening) = PedersenCommitment::commit(20, &mut OsRng);
let (b, b_opening) = PedersenCommitment::commit(22, &mut OsRng);
let sum = a.combine(&b);
let sum_opening = a_opening.combine(&b_opening);
assert!(sum.verify_opening(&sum_opening));

let context = b"my-app/opening/session-123";
let proof = PedersenProof::prove(&sum_opening, context, &mut OsRng);
proof.verify(&sum, context)?;
# Ok::<(), zk_proofs::Error>(())
```

The opening proof sends `T = aG + dH` and responses
`z_v = a + cv`, `z_b = d + cb`. The verifier checks
`z_v G + z_b H = T + cC`, with `c` bound to the statement and context.

Opening a commitment reveals its value and blinding. Proving opening knowledge
does not reveal them. Neither operation proves a range, positivity, or absence
of overflow in application-level integer arithmetic. Combined values are
scalars modulo the group order; use `commit_scalar` for arbitrary scalar inputs.

## Ring signatures: one of these keys signed

```rust
use zk_proofs::{OsRng, Ring, RingSignature, SecretKey};

let keys: Vec<_> = (0..3).map(|_| SecretKey::generate(&mut OsRng)).collect();
let ring = Ring::new(keys.iter().map(SecretKey::public_key).collect())?;
let context = b"my-app/vote/round-7";
let message = b"approve";

let signature = RingSignature::sign(&keys[1], &ring, context, message, &mut OsRng)?;
let received = RingSignature::from_bytes(&signature.to_bytes())?;
received.verify(&ring, context, message)?;
assert!(received.verify(&ring, context, b"reject").is_err());
# Ok::<(), zk_proofs::Error>(())
```

The signature combines a real Schnorr branch with simulated branches. Its
challenges sum to a hash of all reconstructed commitments, the full ordered
ring, context, and message. No signer index is included in the encoding.

A ring must have 2–1024 distinct nonidentity public keys. Changing ring order,
membership, context, or message invalidates a signature. Applications must
decide which ring members are eligible and how keys are authenticated.

## Formats and errors

| Public object | Encoded size |
| --- | --- |
| Public key / Pedersen commitment | 32 bytes |
| Interactive challenge / response | 32 bytes each |
| Schnorr non-interactive proof | 64 bytes |
| Pedersen opening proof | 96 bytes |
| Ring signature with n members | 4 + 64n bytes |

Decoders reject invalid lengths, trailing bytes, noncanonical scalars, and
invalid point encodings. Identity public keys and identity Schnorr commitments
are rejected. **Decoding is not verification.** Verification returns
`Result<(), Error>`; an invalid opening returns `false`.

Secret key exports contain 32 bytes and Pedersen opening exports contain 64
bytes of **secret data**, separate from public proofs. Stored secret scalars are zeroized on drop, and debug output is
redacted. Exported buffers and caller-owned copies need separate protection.

The exact transcript and byte layouts are in [docs/PROTOCOLS.md](https://github.com/echostacc/zk-proofs/blob/main/docs/PROTOCOLS.md).
Migration from the old `u64` API is described in [CHANGELOG.md](https://github.com/echostacc/zk-proofs/blob/main/CHANGELOG.md).

## Development

See [CONTRIBUTING.md](https://github.com/echostacc/zk-proofs/blob/main/CONTRIBUTING.md). CI runs formatting, strict Clippy,
tests, doctests, documentation, examples, and package validation.
The lockfile is committed for reproducible repository builds.

## References

- [Schnorr proofs and Fiat-Shamir, RFC 8235](https://www.rfc-editor.org/rfc/rfc8235.html)
- [Pedersen commitments, ZKDocs](https://www.zkdocs.com/docs/zkdocs/commitments/pedersen/)
- [Sigma protocols and OR composition, Ivan Damgård](https://cs.au.dk/~ivan/Sigma.pdf)
- [Ristretto255, RFC 9496](https://www.rfc-editor.org/rfc/rfc9496.html)
- [curve25519-dalek documentation](https://docs.rs/curve25519-dalek/5.0.0/curve25519_dalek/)

These explain the building blocks; this crate is an educational implementation,
not an interoperable implementation of every referenced specification.

## License

[MIT](https://github.com/echostacc/zk-proofs/blob/main/LICENSE).
