use zk_proofs::schnorr::{SchnorrKeypair, SchnorrParams, SchnorrProof};

fn schnorr_demo() {
    let params = SchnorrParams::new();
    let keypair = SchnorrKeypair::generate(&params);

    println!("Schnorr Zero-Knowledge Proof Demo");
    println!("============================\n");
    println!("Parameters: p = {}, g = {}", params.p, params.g);
    println!("Prover's secret key: {}", keypair.secret_key);
    println!("Public key: {}", keypair.public_key);

    // Commitment
    let (commitment, r) = SchnorrProof::create_commitment(&params);
    println!("\n--- Phase 1: Commitment ---");
    println!("Random r = {}", r);
    println!("Prover sends commitment t = {}", commitment);

    // Challenge (verifier generates a random challenge)
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let challenge = rng.gen_range(1..params.p); // random challenge in range [1, p-1]
    println!("\n--- Phase 2: Challenge ---");
    println!("Verifier sends challenge c = {}", challenge);

    // Response
    let response = SchnorrProof::create_response(r, challenge, keypair.secret_key, params.p);
    println!("\n--- Phase 3: Response ---");
    println!("Prover sends response s = {}", response);

    // Constructing the proof and verifying it
    let proof = SchnorrProof {
        commitment,
        challenge,
        response,
    };

    // Verification
    let is_valid = proof.verify(&params, keypair.public_key);
    println!("\n--- Phase 4: Verification ---");
    println!("Proof is valid: {}", is_valid);
}

fn main() {
    schnorr_demo();
}