#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod error;
mod internal;
mod keys;
pub mod pedersen;
pub mod ring;
pub mod schnorr;

pub use curve25519_dalek::scalar::Scalar;
pub use error::Error;
pub use keys::{PublicKey, SecretKey};
pub use pedersen::{PedersenCommitment, PedersenOpening, PedersenProof};
pub use rand_core::{CryptoRng, OsRng, RngCore};
pub use ring::{MAX_RING_SIZE, Ring, RingSignature};
pub use schnorr::{SchnorrChallenge, SchnorrCommitment, SchnorrProof, SchnorrResponse};
