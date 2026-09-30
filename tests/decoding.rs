use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use zk_proofs::{
    MAX_RING_SIZE, PedersenCommitment, PedersenOpening, PedersenProof, Ring, RingSignature,
    RngCore, SchnorrProof, SecretKey,
};

#[test]
fn fixed_size_decoders_reject_truncation_and_trailing_bytes() {
    let mut rng = ChaCha20Rng::from_seed([7; 32]);
    let key = SecretKey::generate(&mut rng);
    let schnorr = SchnorrProof::prove(&key, b"test", &mut rng).to_bytes();
    let (_, opening) = PedersenCommitment::commit(42, &mut rng);
    let pedersen = PedersenProof::prove(&opening, b"test", &mut rng).to_bytes();
    for len in 0..64 {
        assert!(SchnorrProof::from_bytes(&schnorr[..len]).is_err());
        assert!(PedersenOpening::from_bytes(&opening.to_bytes()[..len]).is_err());
    }
    for len in 0..96 {
        assert!(PedersenProof::from_bytes(&pedersen[..len]).is_err());
    }
    assert!(SchnorrProof::from_bytes(&[schnorr.as_slice(), &[0]].concat()).is_err());
    assert!(PedersenProof::from_bytes(&[pedersen.as_slice(), &[0]].concat()).is_err());
    assert!(PedersenOpening::from_bytes(&[opening.to_bytes().as_slice(), &[0]].concat()).is_err());
}

#[test]
fn fixed_size_decoders_reject_noncanonical_points_and_scalars() {
    let mut rng = ChaCha20Rng::from_seed([7; 32]);
    let key = SecretKey::generate(&mut rng);
    let proof = SchnorrProof::prove(&key, b"test", &mut rng).to_bytes();
    for offset in [0, 32] {
        let mut bytes = proof;
        bytes[offset..offset + 32].fill(255);
        assert!(SchnorrProof::from_bytes(&bytes).is_err());
    }
    let mut identity = proof;
    identity[..32].fill(0);
    assert!(SchnorrProof::from_bytes(&identity).is_err());
    let (_, opening) = PedersenCommitment::commit(42, &mut rng);
    let proof = PedersenProof::prove(&opening, b"test", &mut rng).to_bytes();
    for offset in [0, 32, 64] {
        let mut bytes = proof;
        bytes[offset..offset + 32].fill(255);
        assert!(PedersenProof::from_bytes(&bytes).is_err());
    }
    for offset in [0, 32] {
        let mut bytes = opening.to_bytes();
        bytes[offset..offset + 32].fill(255);
        assert!(PedersenOpening::from_bytes(&bytes).is_err());
    }
    assert!(PedersenCommitment::from_bytes([255; 32]).is_err());
}

#[test]
fn ring_decoder_checks_header_length_bounds_and_canonical_scalars() {
    let mut rng = ChaCha20Rng::from_seed([7; 32]);
    let a = SecretKey::generate(&mut rng);
    let b = SecretKey::generate(&mut rng);
    let ring = Ring::new(vec![a.public_key(), b.public_key()]).unwrap();
    let wire = RingSignature::sign(&a, &ring, b"test", b"message", &mut rng)
        .unwrap()
        .to_bytes();
    for len in 0..wire.len() {
        assert!(RingSignature::from_bytes(&wire[..len]).is_err());
    }
    assert!(RingSignature::from_bytes(&[wire.as_slice(), &[0]].concat()).is_err());
    for count in [0, 1, 3, MAX_RING_SIZE as u32 + 1, u32::MAX] {
        let mut bytes = wire.clone();
        bytes[..4].copy_from_slice(&count.to_le_bytes());
        assert!(RingSignature::from_bytes(&bytes).is_err());
    }
    for offset in (4..wire.len()).step_by(32) {
        let mut bytes = wire.clone();
        bytes[offset..offset + 32].fill(255);
        assert!(RingSignature::from_bytes(&bytes).is_err());
    }
    // The largest permitted count is decodable without requiring a valid proof.
    let mut largest = vec![0; 4 + 64 * MAX_RING_SIZE];
    largest[..4].copy_from_slice(&(MAX_RING_SIZE as u32).to_le_bytes());
    assert!(RingSignature::from_bytes(&largest).is_ok());
}

#[test]
fn arbitrary_decoder_inputs_never_panic() {
    let mut rng = ChaCha20Rng::from_seed([99; 32]);
    for length in 0..=256 {
        let mut bytes = vec![0; length];
        rng.fill_bytes(&mut bytes);
        let _ = SchnorrProof::from_bytes(&bytes);
        let _ = PedersenProof::from_bytes(&bytes);
        let _ = PedersenOpening::from_bytes(&bytes);
        let _ = RingSignature::from_bytes(&bytes);
    }
}
