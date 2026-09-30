//! Pedersen commitments, homomorphic addition, and proofs of opening knowledge.
//!
//! A commitment is `C = vG + bH`. The second generator is derived by hashing
//! a fixed domain to a Ristretto point, without choosing a known scalar times G.
//! A commitment by itself is not a zero-knowledge proof or a range proof.

use std::{fmt, sync::OnceLock};

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{Error, internal, internal::Transcript};

fn blinding_generator() -> &'static RistrettoPoint {
    static GENERATOR: OnceLock<RistrettoPoint> = OnceLock::new();
    GENERATOR.get_or_init(|| {
        let uniform = Sha512::digest(b"zk-proofs/v0.2/pedersen/H/ristretto255");
        RistrettoPoint::from_uniform_bytes(&uniform.into())
    })
}

fn commit_scalars(value: &Scalar, blinding: &Scalar) -> RistrettoPoint {
    value * RISTRETTO_BASEPOINT_POINT + blinding * blinding_generator()
}

/// A 32-byte Pedersen commitment to a scalar value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PedersenCommitment(RistrettoPoint);

impl PedersenCommitment {
    /// Commit to a `u64` with a fresh random blinding factor.
    pub fn commit<R: RngCore + CryptoRng>(value: u64, rng: &mut R) -> (Self, PedersenOpening) {
        Self::commit_scalar(Scalar::from(value), rng)
    }

    /// Commit to any scalar; arithmetic is modulo the Ristretto group order.
    pub fn commit_scalar<R: RngCore + CryptoRng>(
        value: Scalar,
        rng: &mut R,
    ) -> (Self, PedersenOpening) {
        let value = Zeroizing::new(value);
        let blinding = Zeroizing::new(internal::random_scalar(rng));
        let opening = PedersenOpening {
            value: *value,
            blinding: *blinding,
        };
        (opening.commitment(), opening)
    }

    /// Check an opening, revealing its value and blinding to the verifier.
    pub fn verify_opening(&self, opening: &PedersenOpening) -> bool {
        *self == opening.commitment()
    }

    /// Add commitments; the result commits to the sum of the openings.
    pub fn combine(&self, other: &Self) -> Self {
        Self(self.0 + other.0)
    }

    /// Encode the commitment as 32 canonical Ristretto bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }

    /// Decode a commitment. The identity is valid, for example for zero sums.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, Error> {
        Ok(Self(internal::decode_point(&bytes)?))
    }
}

/// The secret value and blinding factor for a Pedersen commitment.
///
/// Stored scalars are zeroized on drop; debug output is redacted.
#[derive(ZeroizeOnDrop)]
pub struct PedersenOpening {
    value: Scalar,
    blinding: Scalar,
}

impl PedersenOpening {
    /// Recompute the public commitment associated with this opening.
    pub fn commitment(&self) -> PedersenCommitment {
        PedersenCommitment(commit_scalars(&self.value, &self.blinding))
    }

    /// Combine openings, adding values and blindings modulo the group order.
    pub fn combine(&self, other: &Self) -> Self {
        Self {
            value: self.value + other.value,
            blinding: self.blinding + other.blinding,
        }
    }

    /// Export `value || blinding` as 64 bytes of **secret data**.
    ///
    /// Sharing these bytes opens the commitment. Protect or erase the returned
    /// buffer yourself; its lifetime is not managed by this type.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(self.value.as_bytes());
        bytes[32..].copy_from_slice(self.blinding.as_bytes());
        bytes
    }

    /// Import two canonical scalars from a secret opening buffer.
    ///
    /// Caller-owned bytes are not zeroized by this method.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 64 {
            return Err(Error::InvalidEncoding);
        }
        let value = Zeroizing::new(internal::decode_scalar(&bytes[..32])?);
        let blinding = Zeroizing::new(internal::decode_scalar(&bytes[32..])?);
        Ok(Self {
            value: *value,
            blinding: *blinding,
        })
    }
}

impl fmt::Debug for PedersenOpening {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PedersenOpening([REDACTED])")
    }
}

/// A 96-byte Fiat-Shamir proof of knowledge of a commitment's opening.
///
/// It proves knowledge of both scalars without revealing them. It does not
/// prove that the value is positive, bounded, or meaningful to an application.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PedersenProof {
    announcement: RistrettoPoint,
    value_response: Scalar,
    blinding_response: Scalar,
}

impl PedersenProof {
    /// Prove knowledge of an opening with fresh random nonces.
    pub fn prove<R: RngCore + CryptoRng>(
        opening: &PedersenOpening,
        context: &[u8],
        rng: &mut R,
    ) -> Self {
        let value_nonce = Zeroizing::new(internal::random_scalar(rng));
        let blinding_nonce = Zeroizing::new(internal::random_scalar(rng));
        let announcement = commit_scalars(&value_nonce, &blinding_nonce);
        let challenge = proof_challenge(&opening.commitment(), &announcement, context);
        Self {
            announcement,
            value_response: *value_nonce + challenge * opening.value,
            blinding_response: *blinding_nonce + challenge * opening.blinding,
        }
    }

    /// Verify against the expected commitment and application context.
    pub fn verify(&self, commitment: &PedersenCommitment, context: &[u8]) -> Result<(), Error> {
        let challenge = proof_challenge(commitment, &self.announcement, context);
        if commit_scalars(&self.value_response, &self.blinding_response)
            == self.announcement + challenge * commitment.0
        {
            Ok(())
        } else {
            Err(Error::InvalidProof)
        }
    }

    /// Encode `T || z_value || z_blinding` as 96 bytes.
    pub fn to_bytes(&self) -> [u8; 96] {
        let mut bytes = [0u8; 96];
        bytes[..32].copy_from_slice(self.announcement.compress().as_bytes());
        bytes[32..64].copy_from_slice(self.value_response.as_bytes());
        bytes[64..].copy_from_slice(self.blinding_response.as_bytes());
        bytes
    }

    /// Decode canonical points and scalars. Verification is still required.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 96 {
            return Err(Error::InvalidEncoding);
        }
        Ok(Self {
            announcement: internal::decode_point(&bytes[..32])?,
            value_response: internal::decode_scalar(&bytes[32..64])?,
            blinding_response: internal::decode_scalar(&bytes[64..])?,
        })
    }
}

fn proof_challenge(
    commitment: &PedersenCommitment,
    announcement: &RistrettoPoint,
    context: &[u8],
) -> Scalar {
    let mut transcript = Transcript::new(b"zk-proofs/v0.2/pedersen-opening/ristretto255");
    transcript.append(
        b"value-generator",
        RISTRETTO_BASEPOINT_POINT.compress().as_bytes(),
    );
    transcript.append(
        b"blinding-generator",
        blinding_generator().compress().as_bytes(),
    );
    transcript.append(b"commitment", &commitment.to_bytes());
    transcript.append(b"announcement", announcement.compress().as_bytes());
    transcript.append(b"context", context);
    transcript.challenge()
}
