use zk_proofs::{Error, OsRng, SchnorrChallenge, SchnorrCommitment, SchnorrProof, SecretKey};

fn main() -> Result<(), Error> {
    let mut rng = OsRng;
    let key = SecretKey::generate(&mut rng);
    let public = key.public_key();
    println!("Schnorr proofs over Ristretto255 (educational, unaudited)");
    println!("Public key: {:02x?}", public.to_bytes());

    let prover = SchnorrCommitment::new(&key, &mut rng);
    let commitment = prover.commitment();
    println!("1. Prover sends commitment: {commitment:02x?}");
    let challenge = SchnorrChallenge::generate(&mut rng);
    println!("2. Verifier sends challenge: {:02x?}", challenge.to_bytes());
    let response = prover.respond(&challenge);
    println!("3. Prover sends response: {:02x?}", response.to_bytes());
    response.verify(&public, commitment, &challenge)?;
    println!("Interactive proof verified.");

    let context = b"zk-proofs/example/schnorr/session-1";
    let proof = SchnorrProof::prove(&key, context, &mut rng);
    let received = SchnorrProof::from_bytes(&proof.to_bytes())?;
    received.verify(&public, context)?;
    println!("Non-interactive proof verified (64 bytes).");
    assert!(received.verify(&public, b"different-session").is_err());
    println!("Changed context rejected.");
    Ok(())
}
