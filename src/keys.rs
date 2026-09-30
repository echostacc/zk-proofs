use std::fmt;

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
    traits::IsIdentity,
};
use rand_core::{CryptoRng, RngCore};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{Error, internal};

/// A nonzero secret scalar shared by Schnorr proofs and ring signatures.
///
/// It is not clonable, its debug output is redacted, and its stored scalar is
/// zeroized on drop. Protect any caller-owned secret bytes separately.
#[derive(ZeroizeOnDrop)]
pub struct SecretKey(Scalar);

impl SecretKey {
    /// Generate a key using a cryptographically secure random number generator.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(internal::random_nonzero_scalar(rng))
    }

    /// Import a canonical, little-endian nonzero scalar.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, Error> {
        let bytes = Zeroizing::new(bytes);
        let scalar = Zeroizing::new(
            internal::decode_scalar(bytes.as_ref()).map_err(|_| Error::InvalidSecretKey)?,
        );
        if *scalar == Scalar::ZERO {
            return Err(Error::InvalidSecretKey);
        }
        Ok(Self(*scalar))
    }

    /// Compute the corresponding public key `P = xG`.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0 * RISTRETTO_BASEPOINT_POINT)
    }

    /// Export the canonical scalar as 32 bytes of **secret data**.
    ///
    /// Protect or erase the returned buffer yourself. Zeroizing this key on
    /// drop cannot erase exported copies.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub(crate) fn scalar(&self) -> &Scalar {
        &self.0
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey([REDACTED])")
    }
}

/// A validated, nonidentity Ristretto255 public key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicKey(pub(crate) RistrettoPoint);

impl PublicKey {
    /// Decode a canonical Ristretto point and reject the identity.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, Error> {
        let point = internal::decode_point(&bytes)?;
        if point.is_identity() {
            return Err(Error::InvalidPublicKey);
        }
        Ok(Self(point))
    }

    /// Encode the public key as 32 canonical bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }
}
