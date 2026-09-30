# Protocol and encoding specification (v0.2)

This document fixes the crate-specific formats used by version 0.2. It does not
claim interoperability with Bitcoin, RFC 8235, or any existing ring-signature
wire protocol.

## Common conventions

- Group: Ristretto255, with standard generator G.
- Scalar order: L = 2^252 + 27742317777372353535851937790883648493.
- Group points: 32-byte canonical compressed Ristretto encodings.
- Scalars: 32-byte little-endian canonical integers in [0, L).
- Secret keys: nonzero scalars. Public keys: P = xG, excluding the identity.
- Random scalar: 64 cryptographically random bytes reduced modulo L.
- Secret keys and Schnorr nonces resample zero. Pedersen blindings, Pedersen proof
  nonces, ring nonces, and simulated ring scalars include zero.
- All additions and multiplications of scalars are modulo L.

The identity is valid for Pedersen commitments and OR-proof announcements.
Schnorr commitments exclude the identity because this implementation samples
nonzero Schnorr nonces. A zero interactive challenge or response is a valid
scalar; verifiers must use a genuinely random, fresh challenge.

## Transcript framing

Each appended field with byte label `label` and value `value` contributes:

```text
u64_le(label.len) || label || u64_le(value.len) || value
```

Start with a field labelled `domain` containing the protocol domain below.
Append all remaining fields in the documented order. SHA-512 hashes the complete
framed transcript. Interpret its 64-byte output as a little-endian integer and
reduce modulo L to produce the challenge. Domains include the group and format
version. Contexts and messages are raw public bytes, without string conversion.

## Interactive Schnorr

1. The prover sends R = rG with fresh nonzero r.
2. The verifier samples c after receiving R.
3. The prover sends z = r + cx.
4. The verifier checks zG = R + cP against its retained R and c.

Messages are separate 32-byte encodings: R (point), c (scalar), z (scalar).
The nonce state is private, borrows the key, and is consumed by responding.
There is no self-contained interactive proof format or prover-supplied challenge
accepted by verification.

## Non-interactive Schnorr

Domain: `zk-proofs/v0.2/schnorr-nizk/ristretto255`

| Order | Label | Value |
| --- | --- | --- |
| 1 | generator | compressed G |
| 2 | public-key | compressed P |
| 3 | commitment | compressed R |
| 4 | context | application context |

Derive c from this transcript and compute z = r + cx.
Verification recomputes c and checks zG = R + cP.

Encoding: `R (32) || z (32)`, exactly 64 bytes. R must be a nonidentity point.
The challenge is recomputed, not transmitted.

## Pedersen commitment and opening

Derive H as follows:

```text
uniform = SHA512("zk-proofs/v0.2/pedersen/H/ristretto255")
H = RistrettoPoint::from_uniform_bytes(uniform)
C = vG + bH
```

H is obtained by the Ristretto uniform-byte map, not by hashing to a scalar and
multiplying G. A known discrete-log relationship would destroy binding.

Public commitment: compressed C, exactly 32 bytes.
Secret opening: `v (32) || b (32)`, exactly 64 bytes.
Both opening scalars are canonical; zero and identity commitments are valid.
Adding commitments and openings adds their values and blindings modulo L.

## Pedersen opening knowledge proof

Sample independent a and d. Compute T = aG + dH, and derive c using:

Domain: `zk-proofs/v0.2/pedersen-opening/ristretto255`

| Order | Label | Value |
| --- | --- | --- |
| 1 | value-generator | compressed G |
| 2 | blinding-generator | compressed H |
| 3 | commitment | compressed C |
| 4 | announcement | compressed T |
| 5 | context | application context |

Return z_v = a + cv and z_b = d + cb.
Verify z_v G + z_b H = T + cC.

Encoding: `T (32) || z_v (32) || z_b (32)`, exactly 96 bytes.
T may be the identity. There is no range statement in this proof.

## Ring signature (Schnorr OR proof)

The ring is an ordered list P_0 ... P_(n-1), with 2 <= n <= 1024 and no repeated
or identity keys. Its order is part of the statement.

For signer j, sample nonce r and set T_j = rG. For each other member i, sample
c_i and s_i independently and set T_i = s_i G - c_i P_i. Hash the following:

Domain: `zk-proofs/v0.2/schnorr-or-ring/ristretto255`

| Order | Label | Value |
| --- | --- | --- |
| 1 | generator | compressed G |
| 2 | ring-size | n as u32 little-endian |
| 3 ... | public-key | each compressed P_i, in ring order |
| next | context | application context |
| next | message | message bytes |
| final ... | announcement | each compressed T_i, in ring order |

Let the result be c. Set c_j = c - sum_(i != j) c_i, and
s_j = r + c_j x_j. Return all pairs (c_i, s_i).

Verification reconstructs every T_i = s_i G - c_i P_i and checks that the
transcript hash equals sum_i c_i. This is additive challenge composition in the
scalar field. It is an educational application of Sigma-protocol OR composition.

Encoding:

```text
n (4, u32 LE) || c_0 (32) || s_0 (32) || ... || c_(n-1) (32) || s_(n-1) (32)
```

The exact length is 4 + 64n. Decoding checks n before allocating, requires
canonical scalars, and accepts no trailing bytes. The verifier separately
supplies the authenticated ring, context, and message. There is no signer
index, key image, linkability, or threshold policy in the format.

## References

- [Ristretto255 specification, RFC 9496](https://www.rfc-editor.org/rfc/rfc9496.html)
- [Schnorr proofs, RFC 8235](https://www.rfc-editor.org/rfc/rfc8235.html)
- [Pedersen commitments, ZKDocs](https://www.zkdocs.com/docs/zkdocs/commitments/pedersen/)
- [Sigma protocols and OR proofs, Ivan Damgård](https://cs.au.dk/~ivan/Sigma.pdf)
