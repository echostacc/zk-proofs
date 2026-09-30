//! Frozen v0.2 byte vectors. Inputs are deliberately public test constants.
//! SHA-512 challenges and scalar responses were independently checked in Python.

use zk_proofs::{
    CryptoRng, PedersenCommitment, PedersenProof, Ring, RingSignature, RngCore, Scalar,
    SchnorrProof, SecretKey,
};

struct Fixed;
impl CryptoRng for Fixed {}
impl RngCore for Fixed {
    fn next_u32(&mut self) -> u32 {
        13
    }
    fn next_u64(&mut self) -> u64 {
        13
    }
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        bytes.fill(0);
        bytes[0] = 13;
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), rand_chacha::rand_core::Error> {
        self.fill_bytes(bytes);
        Ok(())
    }
}

fn expected(name: &str) -> Vec<u8> {
    let hex = include_str!("fixtures/vectors.txt")
        .lines()
        .find_map(|line| {
            line.split_once('=')
                .filter(|(key, _)| *key == name)
                .map(|(_, value)| value)
        })
        .unwrap();
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn key(value: u64) -> SecretKey {
    SecretKey::from_bytes(Scalar::from(value).to_bytes()).unwrap()
}

#[test]
fn schnorr_wire_vector_is_stable() {
    let key = key(7);
    assert_eq!(key.public_key().to_bytes().as_slice(), expected("public_a"));
    let proof = SchnorrProof::prove(&key, b"vector", &mut Fixed);
    assert_eq!(proof.to_bytes().as_slice(), expected("schnorr"));
    SchnorrProof::from_bytes(&expected("schnorr"))
        .unwrap()
        .verify(&key.public_key(), b"vector")
        .unwrap();
}

#[test]
fn pedersen_generator_commitment_and_proof_vectors_are_stable() {
    let (commitment, opening) = PedersenCommitment::commit(42, &mut Fixed);
    assert_eq!(
        commitment.to_bytes().as_slice(),
        expected("pedersen_commitment")
    );
    let proof = PedersenProof::prove(&opening, b"vector", &mut Fixed);
    assert_eq!(proof.to_bytes().as_slice(), expected("pedersen_proof"));
    PedersenProof::from_bytes(&expected("pedersen_proof"))
        .unwrap()
        .verify(&commitment, b"vector")
        .unwrap();
}

#[test]
fn ring_signature_wire_vector_is_stable() {
    let a = key(7);
    let b = key(8);
    let ring = Ring::new(vec![a.public_key(), b.public_key()]).unwrap();
    let signature = RingSignature::sign(&a, &ring, b"vector", b"message", &mut Fixed).unwrap();
    assert_eq!(signature.to_bytes(), expected("ring_signature"));
    RingSignature::from_bytes(&expected("ring_signature"))
        .unwrap()
        .verify(&ring, b"vector", b"message")
        .unwrap();
}
