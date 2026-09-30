# Version 0.2 vectors

These are public test constants, not usable secret keys or production randomness.
The scalar sampler always receives 64 bytes encoding the integer 13. The Schnorr
key is 7, the second ring key is 8, the Pedersen value is 42 with blinding 13,
the context is `vector`, and the ring message is `message`.

For the ring vector, the real branch is the first key, with announcement 13G.
The simulated branch has challenge 13, response 13, and announcement -91G.

`scripts/check_vectors.py` independently verifies all transcript framing,
SHA-512 challenges, and scalar response equations using Python's standard
library. It takes the point encodings as fixed inputs; group operations and the
hash-to-point map are covered by the Rust vector tests using curve25519-dalek.

Changing these fixtures changes the documented v0.2 transcript or encoding.
