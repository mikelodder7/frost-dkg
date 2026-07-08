#[cfg(feature = "bls12_381_plus")]
mod tbls12_381_plus;
#[cfg(feature = "blstrs_plus")]
mod tblstrs_plus;
#[cfg(feature = "curve25519-dalek")]
mod tcurve25519_dalek;
#[cfg(feature = "ed448")]
mod ted448;
#[cfg(feature = "k256")]
mod tk256;
#[cfg(feature = "p256")]
mod tp256;
#[cfg(feature = "p384")]
mod tp384;

use elliptic_curve::PrimeField;

/// A trait for hashing a scalar
pub trait ScalarHash: PrimeField {
    /// Hash a scalar
    fn hash_to_scalar(bytes: &[u8]) -> Self;
}
