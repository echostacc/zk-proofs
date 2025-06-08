# Zero-Knowledge Proofs

## What is Zero-Knowledge Proof?

A cryptographic method where one party (Prover) can prove to another party (Verifier) that they know a value x, without revealing any information about x itself.

## Implemented Protocols

### Schnorr Protocol
Proves knowledge of discrete logarithm. Used in Bitcoin signatures.

**How it works:**
1. **Setup**: Public parameters `p` (prime), `g` (generator)
2. **Key Generation**: 
   - Secret key: `x` (random)
   - Public key: `y = g^x mod p`
3. **Proof Protocol**:
   - Prover generates random `r`, sends commitment `t = g^r mod p`
   - Verifier sends random challenge `c`
   - Prover responds with `s = r + c*x mod (p-1)`
   - Verifier accepts if `g^s = t * y^c mod p`

```bash
cargo run --example schnorr_example
```

### Coming Soon
- **Groth16** - Efficient zk-SNARK construction
- **PLONK** - Universal and updatable trusted setup
- **Bulletproofs** - Short non-interactive zero-knowledge proofs
- **zk-STARKs** - Transparent (no trusted setup) proofs
- **Sigma Protocols** - Foundation for many ZK systems
- **Ring Signatures** - Anonymous signatures
- **Pedersen Commitments** - Hiding and binding commitments
- ... and more

## License

MIT License - see [LICENSE](LICENSE) file.