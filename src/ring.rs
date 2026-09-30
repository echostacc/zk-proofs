//! Unlinkable ring signatures using a Fiat-Shamir Schnorr OR proof.
//!
//! A signature proves knowledge of one key in an ordered ring without encoding
//! which member signed. It binds the full ring, the context, and the message.
//! There are no key images, linkability, or double-spend detection.

use std::collections::HashSet;

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::{Error, PublicKey, SecretKey, internal, internal::Transcript};

/// Maximum ring size accepted by constructors and signature decoders.
///
/// This bounds allocations and work for untrusted inputs; verification is O(n).
pub const MAX_RING_SIZE: usize = 1024;

/// An ordered set of two or more distinct, validated public keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ring(Vec<PublicKey>);

impl Ring {
    /// Validate the ring size and reject duplicate keys, preserving order.
    pub fn new(public_keys: Vec<PublicKey>) -> Result<Self, Error> {
        if !(2..=MAX_RING_SIZE).contains(&public_keys.len()) {
            return Err(Error::InvalidRing);
        }
        let unique: HashSet<_> = public_keys.iter().map(PublicKey::to_bytes).collect();
        if unique.len() != public_keys.len() {
            return Err(Error::InvalidRing);
        }
        Ok(Self(public_keys))
    }

    /// Return the public keys in their transcript order.
    pub fn public_keys(&self) -> &[PublicKey] {
        &self.0
    }
}

/// A ring signature with one canonical challenge and response per member.
///
/// Serialized size is `4 + 64 * n` bytes; the signer index is not serialized.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RingSignature {
    challenges: Vec<Scalar>,
    responses: Vec<Scalar>,
}

impl RingSignature {
    /// Sign a message as one member of the supplied ring.
    ///
    /// Include the application domain in the context. Signing is not designed
    /// to conceal the signer index from local timing or memory observers.
    pub fn sign<R: RngCore + CryptoRng>(
        key: &SecretKey,
        ring: &Ring,
        context: &[u8],
        message: &[u8],
        rng: &mut R,
    ) -> Result<Self, Error> {
        let public = key.public_key();
        let signer = ring
            .0
            .iter()
            .position(|candidate| *candidate == public)
            .ok_or(Error::KeyNotInRing)?;
        let n = ring.0.len();
        let nonce = Zeroizing::new(internal::random_scalar(rng));
        let mut challenges = vec![Scalar::ZERO; n];
        let mut responses = vec![Scalar::ZERO; n];
        let mut announcements = Vec::with_capacity(n);
        let mut simulated_sum = Scalar::ZERO;

        for (i, public_key) in ring.0.iter().enumerate() {
            if i == signer {
                announcements.push(*nonce * RISTRETTO_BASEPOINT_POINT);
            } else {
                challenges[i] = internal::random_scalar(rng);
                responses[i] = internal::random_scalar(rng);
                announcements
                    .push(responses[i] * RISTRETTO_BASEPOINT_POINT - challenges[i] * public_key.0);
                simulated_sum += challenges[i];
            }
        }

        // Simulate all other Schnorr branches and close the challenge sum with
        // the one branch for which we know a witness.
        challenges[signer] =
            signature_challenge(ring, context, message, &announcements) - simulated_sum;
        responses[signer] = *nonce + challenges[signer] * key.scalar();
        Ok(Self {
            challenges,
            responses,
        })
    }

    /// Verify the challenge sum against the expected ring, context, and message.
    pub fn verify(&self, ring: &Ring, context: &[u8], message: &[u8]) -> Result<(), Error> {
        if self.challenges.len() != ring.0.len() || self.responses.len() != ring.0.len() {
            return Err(Error::InvalidProof);
        }
        let announcements: Vec<_> = ring
            .0
            .iter()
            .enumerate()
            .map(|(i, public)| {
                self.responses[i] * RISTRETTO_BASEPOINT_POINT - self.challenges[i] * public.0
            })
            .collect();
        let expected = signature_challenge(ring, context, message, &announcements);
        let sum: Scalar = self.challenges.iter().sum();
        if expected == sum {
            Ok(())
        } else {
            Err(Error::InvalidProof)
        }
    }

    /// Encode `n (u32 LE) || c_0 || s_0 || ... || c_(n-1) || s_(n-1)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 + 64 * self.challenges.len());
        bytes.extend_from_slice(&(self.challenges.len() as u32).to_le_bytes());
        for (challenge, response) in self.challenges.iter().zip(&self.responses) {
            bytes.extend_from_slice(challenge.as_bytes());
            bytes.extend_from_slice(response.as_bytes());
        }
        bytes
    }

    /// Decode a signature, checking its size before allocating scalar vectors.
    ///
    /// Decoding does not establish membership or signature validity.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let count: [u8; 4] = bytes
            .get(..4)
            .ok_or(Error::InvalidEncoding)?
            .try_into()
            .map_err(|_| Error::InvalidEncoding)?;
        let n = u32::from_le_bytes(count) as usize;
        if !(2..=MAX_RING_SIZE).contains(&n) || bytes.len() != 4 + 64 * n {
            return Err(Error::InvalidEncoding);
        }
        let mut challenges = Vec::with_capacity(n);
        let mut responses = Vec::with_capacity(n);
        for pair in bytes[4..].chunks_exact(64) {
            challenges.push(internal::decode_scalar(&pair[..32])?);
            responses.push(internal::decode_scalar(&pair[32..])?);
        }
        Ok(Self {
            challenges,
            responses,
        })
    }
}

fn signature_challenge(
    ring: &Ring,
    context: &[u8],
    message: &[u8],
    announcements: &[RistrettoPoint],
) -> Scalar {
    let mut transcript = Transcript::new(b"zk-proofs/v0.2/schnorr-or-ring/ristretto255");
    transcript.append(
        b"generator",
        RISTRETTO_BASEPOINT_POINT.compress().as_bytes(),
    );
    transcript.append(b"ring-size", &(ring.0.len() as u32).to_le_bytes());
    for public in &ring.0 {
        transcript.append(b"public-key", &public.to_bytes());
    }
    transcript.append(b"context", context);
    transcript.append(b"message", message);
    for announcement in announcements {
        transcript.append(b"announcement", announcement.compress().as_bytes());
    }
    transcript.challenge()
}
