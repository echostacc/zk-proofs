# Security and scope

## Intended use

Version 0.2 is an educational implementation of Schnorr proofs, Pedersen
commitments and opening proofs, and unlinkable Schnorr OR ring signatures.
It is unaudited and must not be used to protect funds, credentials, or sensitive
production data. A complete production design requires independent review of
the protocol, implementation, randomness, deployment, and application semantics.

## Assumptions

- Group operations and canonical encoding use curve25519-dalek's Ristretto255
  prime-order group. Discrete logarithms are assumed hard in this group.
- Fiat-Shamir challenges use SHA-512 with separate protocol domains and framed
  fields. Their usual security arguments require a random-oracle model.
- Randomness comes from caller-supplied `RngCore + CryptoRng`; examples use
  `OsRng`. A marker trait cannot guarantee the quality of a custom generator.
- Independent nonce generation is essential. Do not use seeded test RNGs in
  real applications, repeat seeds, clone RNG state, or reuse nonce material.
- Pedersen binding assumes nobody knows the discrete logarithm of the fixed
  hash-derived generator H relative to G. Fresh, effectively uniform blinding
  is required for hiding; scalar sampling reduces 64 random bytes modulo the
  group order, with negligible statistical bias.

## What the API enforces

- Nonzero, canonical secret keys and nonidentity public keys.
- Canonical point and scalar decoding, exact lengths, and no trailing bytes.
- One-use interactive Schnorr nonce state consumed by `respond`.
- Non-interactive challenges recomputed from the expected statement and context.
- Ring membership of the signing key, distinct keys, ring order binding, and a
  maximum of 1024 members before signature-decoder allocations.
- Redacted debug output and zeroization of stored secret scalars on drop.
- No unsafe code in this crate. Dependencies have their own implementations.

## Application responsibilities and limitations

Interactive Schnorr provides honest-verifier zero-knowledge. A verifier must
generate its challenge after the commitment and retain both for verification.
Accepting a transcript chosen entirely by a prover is not proof of knowledge.

A valid non-interactive proof or signature can be replayed with identical
inputs. Provide an application-specific context and a fresh session identifier
when needed; enforce freshness in the application.

Keys are not certificates. Applications must authenticate public keys, choose
eligible ring members, and protect the integrity of expected statements.
A malicious party can fill a ring with keys it controls; the library does not
make an external anonymity claim about such a ring.

Pedersen commitments are not range proofs. Knowledge of an opening does not
establish positivity, an upper bound, or an application-level balance rule.
All arithmetic is modulo the group order. Opening exports reveal both scalars.

Ring signatures are unlinkable and lack key images, signer revocation, and
double-spend detection. Their construction is a scalar-field Schnorr OR proof,
not a compatible implementation of Monero, LSAG, or a threshold scheme.

Signing branches and membership searches depend on the signer index. This code
does not promise anonymity against local timing, cache, or memory observers.
Zeroization cannot erase compiler-generated copies, registers, swap, crash
dumps, exported buffers, or caller-owned copies. It does not replace key storage.

Randomness failures may panic through the RNG's `fill_bytes` implementation.
Applications needing recoverable entropy failures must supply and manage a
suitable generator. Contexts and messages are unbounded byte slices; callers
must enforce transport and resource limits.

## Reporting a vulnerability

For a potential vulnerability, contact the maintainer at **echostacc@pm.me**
(the address listed in Cargo.toml) with affected versions and reproduction
details. Please avoid putting sensitive exploitation details in a public issue
before coordinating disclosure. There is no promised response SLA.
