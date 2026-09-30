use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, ristretto::CompressedRistretto};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use zk_proofs::{
    CryptoRng, Error, MAX_RING_SIZE, PedersenCommitment, PedersenOpening, PedersenProof, PublicKey,
    Ring, RingSignature, RngCore, Scalar, SchnorrChallenge, SchnorrCommitment, SchnorrProof,
    SchnorrResponse, SecretKey,
};

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([42; 32])
}
fn key(value: u64) -> SecretKey {
    SecretKey::from_bytes(Scalar::from(value).to_bytes()).unwrap()
}

fn increment_scalar(bytes: &mut [u8]) {
    let scalar =
        Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes.try_into().unwrap())).unwrap();
    bytes.copy_from_slice(&(scalar + Scalar::ONE).to_bytes());
}

fn move_point(bytes: &mut [u8]) {
    let point = CompressedRistretto(bytes.try_into().unwrap())
        .decompress()
        .unwrap();
    bytes.copy_from_slice(&(point + RISTRETTO_BASEPOINT_POINT).compress().to_bytes());
}

// Test-only deterministic nonce: the 64-byte scalar sample represents 13.
struct KnownNonce;
impl CryptoRng for KnownNonce {}
impl RngCore for KnownNonce {
    fn next_u32(&mut self) -> u32 {
        13
    }
    fn next_u64(&mut self) -> u64 {
        13
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(0);
        dest[0] = 13;
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_chacha::rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

#[test]
fn interactive_schnorr_matches_known_arithmetic() {
    let key = key(7);
    let state = SchnorrCommitment::new(&key, &mut KnownNonce);
    let commitment = state.commitment();
    assert_eq!(
        commitment,
        (Scalar::from(13u64) * RISTRETTO_BASEPOINT_POINT)
            .compress()
            .to_bytes()
    );
    let challenge = SchnorrChallenge::from_bytes(Scalar::from(17u64).to_bytes()).unwrap();
    let response = state.respond(&challenge);
    // 13 + 17 * 7 = 132, independently of the implementation's transcript hash.
    assert_eq!(response.to_bytes(), Scalar::from(132u64).to_bytes());
    response
        .verify(&key.public_key(), commitment, &challenge)
        .unwrap();
}

#[test]
fn interactive_schnorr_requires_expected_key_commitment_and_challenge() {
    let mut rng = rng();
    let key = key(7);
    let state = SchnorrCommitment::new(&key, &mut rng);
    let commitment = state.commitment();
    let challenge = SchnorrChallenge::generate(&mut rng);
    let response = state.respond(&challenge);
    response
        .verify(&key.public_key(), commitment, &challenge)
        .unwrap();
    assert!(
        response
            .verify(&super_key(), commitment, &challenge)
            .is_err()
    );
    let changed = SchnorrChallenge::generate(&mut rng);
    assert!(
        response
            .verify(&key.public_key(), commitment, &changed)
            .is_err()
    );
    let other_state = SchnorrCommitment::new(&key, &mut rng);
    assert!(
        response
            .verify(&key.public_key(), other_state.commitment(), &challenge)
            .is_err()
    );
    assert!(
        response
            .verify(&key.public_key(), [0; 32], &challenge)
            .is_err()
    );
    assert!(
        response
            .verify(&key.public_key(), [255; 32], &challenge)
            .is_err()
    );
}

fn super_key() -> PublicKey {
    key(8).public_key()
}

#[test]
fn schnorr_nizk_binds_key_context_and_every_proof_component() {
    let key = key(7);
    let proof = SchnorrProof::prove(&key, b"context", &mut rng());
    proof.verify(&key.public_key(), b"context").unwrap();
    assert!(proof.verify(&super_key(), b"context").is_err());
    assert!(proof.verify(&key.public_key(), b"changed").is_err());
    let mut changed = proof.to_bytes();
    increment_scalar(&mut changed[32..]);
    assert!(
        SchnorrProof::from_bytes(&changed)
            .unwrap()
            .verify(&key.public_key(), b"context")
            .is_err()
    );
    let mut changed = proof.to_bytes();
    move_point(&mut changed[..32]);
    assert!(
        SchnorrProof::from_bytes(&changed)
            .unwrap()
            .verify(&key.public_key(), b"context")
            .is_err()
    );
}

#[test]
fn public_key_one_matches_standard_ristretto_basepoint() {
    let expected = [
        0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71, 0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00, 0x51,
        0x5f, 0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d, 0xb6, 0xa6, 0x59, 0x45, 0xe0, 0x8d,
        0x2d, 0x76,
    ];
    assert_eq!(key(1).public_key().to_bytes(), expected);
    assert_eq!(
        PublicKey::from_bytes(expected).unwrap(),
        key(1).public_key()
    );
}

#[test]
fn invalid_keys_and_scalars_are_rejected() {
    assert!(matches!(
        SecretKey::from_bytes([0; 32]),
        Err(Error::InvalidSecretKey)
    ));
    assert!(matches!(
        SecretKey::from_bytes([255; 32]),
        Err(Error::InvalidSecretKey)
    ));
    assert_eq!(PublicKey::from_bytes([0; 32]), Err(Error::InvalidPublicKey));
    assert!(PublicKey::from_bytes([255; 32]).is_err());
    assert!(SchnorrChallenge::from_bytes([255; 32]).is_err());
    assert!(SchnorrResponse::from_bytes([255; 32]).is_err());
    // Zero is a canonical challenge/response; a random challenge can equal zero.
    assert!(SchnorrChallenge::from_bytes([0; 32]).is_ok());
    assert!(SchnorrResponse::from_bytes([0; 32]).is_ok());
}

#[test]
fn secret_debug_output_is_redacted() {
    assert_eq!(format!("{:?}", key(7)), "SecretKey([REDACTED])");
    let (_, opening) = PedersenCommitment::commit(42, &mut rng());
    assert_eq!(format!("{opening:?}"), "PedersenOpening([REDACTED])");
    let key = key(7);
    let state = SchnorrCommitment::new(&key, &mut KnownNonce);
    assert!(!format!("{state:?}").contains("nonce"));
}

#[test]
fn pedersen_openings_and_homomorphic_addition_are_consistent() {
    let mut rng = rng();
    let (a, a_opening) = PedersenCommitment::commit(20, &mut rng);
    let (b, b_opening) = PedersenCommitment::commit(22, &mut rng);
    assert!(a.verify_opening(&a_opening));
    assert!(!a.verify_opening(&b_opening));
    let sum = a.combine(&b);
    let opening = a_opening.combine(&b_opening);
    assert!(sum.verify_opening(&opening));
    assert_eq!(&opening.to_bytes()[..32], &Scalar::from(42u64).to_bytes());
    assert_eq!(a.combine(&b), b.combine(&a));
    assert_ne!(a, PedersenCommitment::commit(20, &mut rng).0);
}

#[test]
fn pedersen_proof_binds_statement_context_and_both_responses() {
    let mut rng = rng();
    let (commitment, opening) = PedersenCommitment::commit(42, &mut rng);
    let proof = PedersenProof::prove(&opening, b"context", &mut rng);
    proof.verify(&commitment, b"context").unwrap();
    assert!(proof.verify(&commitment, b"changed").is_err());
    let (other, _) = PedersenCommitment::commit(43, &mut rng);
    assert!(proof.verify(&other, b"context").is_err());
    for offset in [32, 64] {
        let mut changed = proof.to_bytes();
        increment_scalar(&mut changed[offset..offset + 32]);
        assert!(
            PedersenProof::from_bytes(&changed)
                .unwrap()
                .verify(&commitment, b"context")
                .is_err()
        );
    }
    let mut changed = proof.to_bytes();
    move_point(&mut changed[..32]);
    assert!(
        PedersenProof::from_bytes(&changed)
            .unwrap()
            .verify(&commitment, b"context")
            .is_err()
    );
}

#[test]
fn pedersen_supports_zero_max_u64_and_scalar_wraparound() {
    let mut rng = rng();
    for value in [0, u64::MAX] {
        let (commitment, opening) = PedersenCommitment::commit(value, &mut rng);
        assert!(commitment.verify_opening(&opening));
        PedersenProof::prove(&opening, b"edge", &mut rng)
            .verify(&commitment, b"edge")
            .unwrap();
    }
    let (a, ao) = PedersenCommitment::commit_scalar(-Scalar::ONE, &mut rng);
    let (b, bo) = PedersenCommitment::commit(1, &mut rng);
    let opening = ao.combine(&bo);
    assert_eq!(&opening.to_bytes()[..32], &[0; 32]);
    assert!(a.combine(&b).verify_opening(&opening));
    let identity = PedersenCommitment::from_bytes([0; 32]).unwrap();
    let zero = PedersenOpening::from_bytes(&[0; 64]).unwrap();
    assert!(identity.verify_opening(&zero));
    PedersenProof::prove(&zero, b"identity", &mut rng)
        .verify(&identity, b"identity")
        .unwrap();
}

#[test]
fn every_ring_member_can_sign_without_an_encoded_index() {
    let mut rng = rng();
    for size in [2, 5, 12] {
        let keys: Vec<_> = (0..size).map(|_| SecretKey::generate(&mut rng)).collect();
        let ring = Ring::new(keys.iter().map(SecretKey::public_key).collect()).unwrap();
        for key in &keys {
            let signature = RingSignature::sign(key, &ring, b"app", b"message", &mut rng).unwrap();
            signature.verify(&ring, b"app", b"message").unwrap();
            assert_eq!(signature.to_bytes().len(), 4 + 64 * size);
            let decoded = RingSignature::from_bytes(&signature.to_bytes()).unwrap();
            assert_eq!(decoded, signature);
            decoded.verify(&ring, b"app", b"message").unwrap();
        }
    }
}

#[test]
fn ring_signature_binds_ring_order_membership_message_and_context() {
    let mut rng = rng();
    let keys: Vec<_> = (1..=5).map(key).collect();
    let public: Vec<_> = keys.iter().map(SecretKey::public_key).collect();
    let ring = Ring::new(public.clone()).unwrap();
    let signature = RingSignature::sign(&keys[2], &ring, b"a", b"bc", &mut rng).unwrap();
    assert!(signature.verify(&ring, b"a", b"changed").is_err());
    // Concatenated context+message bytes are equal; framing must distinguish them.
    assert!(signature.verify(&ring, b"ab", b"c").is_err());
    let mut reversed = public.clone();
    reversed.reverse();
    assert!(
        signature
            .verify(&Ring::new(reversed).unwrap(), b"a", b"bc")
            .is_err()
    );
    let mut replaced = public.clone();
    replaced[0] = key(99).public_key();
    assert!(
        signature
            .verify(&Ring::new(replaced).unwrap(), b"a", b"bc")
            .is_err()
    );
    assert!(
        signature
            .verify(&Ring::new(public[..4].to_vec()).unwrap(), b"a", b"bc")
            .is_err()
    );
    assert!(matches!(
        RingSignature::sign(&key(99), &ring, b"a", b"bc", &mut rng),
        Err(Error::KeyNotInRing)
    ));
}

#[test]
fn ring_signature_binds_every_challenge_and_response() {
    let ring = Ring::new((1..=4).map(|n| key(n).public_key()).collect()).unwrap();
    let signature = RingSignature::sign(&key(2), &ring, b"app", b"message", &mut rng()).unwrap();
    for offset in (4..signature.to_bytes().len()).step_by(32) {
        let mut changed = signature.to_bytes();
        increment_scalar(&mut changed[offset..offset + 32]);
        assert!(
            RingSignature::from_bytes(&changed)
                .unwrap()
                .verify(&ring, b"app", b"message")
                .is_err()
        );
    }
    let mut forged = vec![0; 4 + 64 * 4];
    forged[..4].copy_from_slice(&4u32.to_le_bytes());
    assert!(
        RingSignature::from_bytes(&forged)
            .unwrap()
            .verify(&ring, b"app", b"message")
            .is_err()
    );
}

#[test]
fn rings_reject_empty_singleton_duplicate_and_oversized_sets() {
    assert_eq!(Ring::new(vec![]), Err(Error::InvalidRing));
    assert_eq!(
        Ring::new(vec![key(1).public_key()]),
        Err(Error::InvalidRing)
    );
    assert_eq!(
        Ring::new(vec![key(1).public_key(); 2]),
        Err(Error::InvalidRing)
    );
    assert_eq!(
        Ring::new(vec![key(1).public_key(); MAX_RING_SIZE + 1]),
        Err(Error::InvalidRing)
    );
    let keys: Vec<_> = (1..=MAX_RING_SIZE as u64)
        .map(|n| key(n).public_key())
        .collect();
    assert!(Ring::new(keys).is_ok());
}

#[test]
fn all_protocols_round_trip_and_use_fresh_randomness() {
    let mut rng = rng();
    for _ in 0..10 {
        let key = SecretKey::generate(&mut rng);
        assert_eq!(
            SecretKey::from_bytes(key.to_bytes()).unwrap().public_key(),
            key.public_key()
        );
        let public = PublicKey::from_bytes(key.public_key().to_bytes()).unwrap();
        let proof = SchnorrProof::prove(&key, b"", &mut rng);
        let decoded = SchnorrProof::from_bytes(&proof.to_bytes()).unwrap();
        assert_eq!(decoded, proof);
        decoded.verify(&public, b"").unwrap();
        assert_ne!(proof, SchnorrProof::prove(&key, b"", &mut rng));
        let state = SchnorrCommitment::new(&key, &mut rng);
        let commitment = state.commitment();
        let challenge = SchnorrChallenge::generate(&mut rng);
        let decoded_challenge = SchnorrChallenge::from_bytes(challenge.to_bytes()).unwrap();
        let response = state.respond(&decoded_challenge);
        SchnorrResponse::from_bytes(response.to_bytes())
            .unwrap()
            .verify(&public, commitment, &challenge)
            .unwrap();
        let (commitment, opening) = PedersenCommitment::commit(rng.next_u64(), &mut rng);
        let decoded_commitment = PedersenCommitment::from_bytes(commitment.to_bytes()).unwrap();
        let decoded_opening = PedersenOpening::from_bytes(&opening.to_bytes()).unwrap();
        assert!(decoded_commitment.verify_opening(&decoded_opening));
        let proof = PedersenProof::prove(&opening, b"", &mut rng);
        assert_eq!(PedersenProof::from_bytes(&proof.to_bytes()).unwrap(), proof);
        proof.verify(&decoded_commitment, b"").unwrap();
        assert_ne!(proof, PedersenProof::prove(&opening, b"", &mut rng));
        let other = SecretKey::generate(&mut rng);
        let ring = Ring::new(vec![public, other.public_key()]).unwrap();
        let signature = RingSignature::sign(&key, &ring, b"", b"", &mut rng).unwrap();
        assert_ne!(
            signature,
            RingSignature::sign(&key, &ring, b"", b"", &mut rng).unwrap()
        );
        signature.verify(&ring, b"", b"").unwrap();
    }
}
