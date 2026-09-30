use zk_proofs::{Error, OsRng, PedersenCommitment, PedersenProof};

fn main() -> Result<(), Error> {
    let mut rng = OsRng;
    let (first, first_opening) = PedersenCommitment::commit(20, &mut rng);
    let (second, second_opening) = PedersenCommitment::commit(22, &mut rng);
    println!("Pedersen commitments (educational, unaudited)");
    println!("First commitment: {:02x?}", first.to_bytes());
    println!("Second commitment: {:02x?}", second.to_bytes());

    let sum = first.combine(&second);
    let sum_opening = first_opening.combine(&second_opening);
    assert!(sum.verify_opening(&sum_opening));
    println!("Combined commitment opens to the sum of the values.");

    let context = b"zk-proofs/example/pedersen/session-1";
    let proof = PedersenProof::prove(&sum_opening, context, &mut rng);
    PedersenProof::from_bytes(&proof.to_bytes())?.verify(&sum, context)?;
    println!("Opening knowledge verified without disclosing the opening (96 bytes).");
    assert!(proof.verify(&first, context).is_err());
    println!("Different commitment rejected.");
    Ok(())
}
