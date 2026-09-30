//! Interactive Schnorr identification and Fiat-Shamir proofs of knowledge.
//!
//! The response is `z = r + cx`, and verification checks `zG = R + cP`.
//! Interactive Schnorr is honest-verifier zero-knowledge: the verifier must
//! sample the challenge after receiving the commitment.

use crate::{Error, PublicKey, SecretKey, internal, internal::Transcript};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
    traits::IsIdentity,
};
use rand_core::{CryptoRng, RngCore};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

/// A prover's one-use nonce and commitment, bound to a secret key.
///
/// Responding consumes the state, preventing accidental nonce reuse:
///
/// ```compile_fail
/// use zk_proofs::{OsRng, SecretKey, SchnorrChallenge, SchnorrCommitment};
/// let key = SecretKey::generate(&mut OsRng);
/// let state = SchnorrCommitment::new(&key, &mut OsRng);
/// let challenge = SchnorrChallenge::generate(&mut OsRng);
/// state.respond(&challenge);
/// state.respond(&challenge); // The nonce state has already been consumed.
/// ```
pub struct SchnorrCommitment<'a> {
    nonce: Scalar,
    commitment: RistrettoPoint,
    key: &'a SecretKey,
}

impl<'a> SchnorrCommitment<'a> {
    /// Create a fresh commitment `R = rG` for an interactive session.
    pub fn new<R: RngCore + CryptoRng>(key: &'a SecretKey, rng: &mut R) -> Self {
        let nonce = Zeroizing::new(internal::random_nonzero_scalar(rng));
        Self {
            nonce: *nonce,
            commitment: *nonce * RISTRETTO_BASEPOINT_POINT,
            key,
        }
    }

    /// Return the public commitment to send before requesting a challenge.
    pub fn commitment(&self) -> [u8; 32] {
        self.commitment.compress().to_bytes()
    }

    /// Answer the verifier's challenge and consume the nonce state.
    pub fn respond(self, challenge: &SchnorrChallenge) -> SchnorrResponse {
        SchnorrResponse(self.nonce + challenge.0 * self.key.scalar())
    }
}

impl Drop for SchnorrCommitment<'_> {
    fn drop(&mut self) {
        self.nonce.zeroize();
    }
}

impl fmt::Debug for SchnorrCommitment<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SchnorrCommitment")
            .field("commitment", &self.commitment())
            .finish_non_exhaustive()
    }
}

/// A verifier-issued challenge for one interactive Schnorr session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchnorrChallenge(Scalar);

impl SchnorrChallenge {
    /// Sample a challenge after receiving the prover's commitment.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(internal::random_scalar(rng))
    }

    /// Decode a canonical scalar challenge received from the verifier.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, Error> {
        Ok(Self(internal::decode_scalar(&bytes)?))
    }

    /// Encode the challenge as 32 bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// A Schnorr response, without a prover-selected challenge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchnorrResponse(Scalar);

impl SchnorrResponse {
    /// Decode a canonical scalar response.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, Error> {
        Ok(Self(internal::decode_scalar(&bytes)?))
    }

    /// Encode the response as 32 bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Verify against the commitment and challenge retained by the verifier.
    ///
    /// A transcript chosen entirely by a prover does not prove knowledge.
    /// Use [`SchnorrProof`] for non-interactive proofs.
    pub fn verify(
        &self,
        public_key: &PublicKey,
        commitment: [u8; 32],
        challenge: &SchnorrChallenge,
    ) -> Result<(), Error> {
        let commitment = decode_commitment(&commitment)?;
        verify_equation(public_key, &commitment, &challenge.0, &self.0)
    }
}

/// A 64-byte Fiat-Shamir Schnorr proof bound to a public key and context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchnorrProof {
    commitment: RistrettoPoint,
    response: Scalar,
}

impl SchnorrProof {
    /// Prove knowledge of the key with a fresh nonce.
    ///
    /// Include an application domain and a session identifier in the public
    /// context if replay prevention is required.
    pub fn prove<R: RngCore + CryptoRng>(key: &SecretKey, context: &[u8], rng: &mut R) -> Self {
        let nonce = Zeroizing::new(internal::random_nonzero_scalar(rng));
        let commitment = *nonce * RISTRETTO_BASEPOINT_POINT;
        let challenge = proof_challenge(&key.public_key(), &commitment, context);
        Self {
            commitment,
            response: *nonce + challenge * key.scalar(),
        }
    }

    /// Recompute the transcript challenge and check the proof equation.
    pub fn verify(&self, public_key: &PublicKey, context: &[u8]) -> Result<(), Error> {
        let challenge = proof_challenge(public_key, &self.commitment, context);
        verify_equation(public_key, &self.commitment, &challenge, &self.response)
    }

    /// Encode `R || z` as 64 bytes.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(self.commitment.compress().as_bytes());
        bytes[32..].copy_from_slice(self.response.as_bytes());
        bytes
    }

    /// Decode a proof, rejecting wrong lengths and noncanonical encodings.
    ///
    /// Decoding alone does not verify a proof.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 64 {
            return Err(Error::InvalidEncoding);
        }
        Ok(Self {
            commitment: decode_commitment(&bytes[..32])?,
            response: internal::decode_scalar(&bytes[32..])?,
        })
    }
}

fn decode_commitment(bytes: &[u8]) -> Result<RistrettoPoint, Error> {
    let point = internal::decode_point(bytes)?;
    if point.is_identity() {
        return Err(Error::InvalidProof);
    }
    Ok(point)
}

fn proof_challenge(public_key: &PublicKey, commitment: &RistrettoPoint, context: &[u8]) -> Scalar {
    let mut transcript = Transcript::new(b"zk-proofs/v0.2/schnorr-nizk/ristretto255");
    transcript.append(
        b"generator",
        RISTRETTO_BASEPOINT_POINT.compress().as_bytes(),
    );
    transcript.append(b"public-key", &public_key.to_bytes());
    transcript.append(b"commitment", commitment.compress().as_bytes());
    transcript.append(b"context", context);
    transcript.challenge()
}

fn verify_equation(
    public_key: &PublicKey,
    commitment: &RistrettoPoint,
    challenge: &Scalar,
    response: &Scalar,
) -> Result<(), Error> {
    if response * RISTRETTO_BASEPOINT_POINT == commitment + challenge * public_key.0 {
        Ok(())
    } else {
        Err(Error::InvalidProof)
    }
}
