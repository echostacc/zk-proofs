use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

use crate::Error;

pub(crate) fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
    let mut wide = Zeroizing::new([0u8; 64]);
    rng.fill_bytes(wide.as_mut());
    Scalar::from_bytes_mod_order_wide(&wide)
}

pub(crate) fn random_nonzero_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
    loop {
        let scalar = Zeroizing::new(random_scalar(rng));
        if *scalar != Scalar::ZERO {
            return *scalar;
        }
    }
}

pub(crate) fn decode_scalar(bytes: &[u8]) -> Result<Scalar, Error> {
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| Error::InvalidEncoding)?;
    Option::from(Scalar::from_canonical_bytes(bytes)).ok_or(Error::InvalidEncoding)
}

pub(crate) fn decode_point(bytes: &[u8]) -> Result<RistrettoPoint, Error> {
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| Error::InvalidEncoding)?;
    CompressedRistretto(bytes)
        .decompress()
        .ok_or(Error::InvalidEncoding)
}

// Length-prefix labels and values so field boundaries are unambiguous.
pub(crate) struct Transcript(Sha512);

impl Transcript {
    pub(crate) fn new(domain: &[u8]) -> Self {
        let mut transcript = Self(Sha512::new());
        transcript.append(b"domain", domain);
        transcript
    }

    pub(crate) fn append(&mut self, label: &[u8], value: &[u8]) {
        self.0.update((label.len() as u64).to_le_bytes());
        self.0.update(label);
        self.0.update((value.len() as u64).to_le_bytes());
        self.0.update(value);
    }

    pub(crate) fn challenge(self) -> Scalar {
        Scalar::from_bytes_mod_order_wide(&self.0.finalize().into())
    }
}
