use zk_proofs::{Error, OsRng, Ring, RingSignature, SecretKey};

fn main() -> Result<(), Error> {
    let mut rng = OsRng;
    let keys: Vec<_> = (0..5).map(|_| SecretKey::generate(&mut rng)).collect();
    let ring = Ring::new(keys.iter().map(SecretKey::public_key).collect())?;
    let context = b"zk-proofs/example/ring";
    let message = b"One member of this ring approves this message.";
    let signature = RingSignature::sign(&keys[2], &ring, context, message, &mut rng)?;
    let received = RingSignature::from_bytes(&signature.to_bytes())?;
    received.verify(&ring, context, message)?;
    println!("Ring signature (educational, unaudited)");
    println!(
        "Verified for a ring of {} public keys.",
        ring.public_keys().len()
    );
    println!("Signature size: {} bytes.", received.to_bytes().len());
    println!("No signer index is included in the signature.");
    assert!(
        received
            .verify(&ring, context, b"Modified message")
            .is_err()
    );
    println!("Modified message rejected.");
    Ok(())
}
