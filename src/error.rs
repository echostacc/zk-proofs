use std::fmt;

/// An invalid encoding, statement, or proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Wrong length, noncanonical scalar, or invalid Ristretto encoding.
    InvalidEncoding,
    /// The identity point cannot be used as a public key.
    InvalidPublicKey,
    /// A secret key must be a nonzero canonical scalar.
    InvalidSecretKey,
    /// The verification equation or transcript challenge does not match.
    InvalidProof,
    /// A ring must have between two and [`crate::MAX_RING_SIZE`] distinct keys.
    InvalidRing,
    /// The signing key's public key is absent from the ring.
    KeyNotInRing,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidEncoding => "invalid or noncanonical encoding",
            Self::InvalidPublicKey => "public key is the identity point",
            Self::InvalidSecretKey => "secret key is zero or noncanonical",
            Self::InvalidProof => "proof verification failed",
            Self::InvalidRing => "ring size is invalid or keys are duplicated",
            Self::KeyNotInRing => "signing key is not a member of the ring",
        })
    }
}

impl std::error::Error for Error {}
