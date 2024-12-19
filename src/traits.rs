#[cfg(feature = "bls")]
mod tbls;
#[cfg(feature = "curve25519")]
mod ted25519;
#[cfg(feature = "ed448")]
mod ted448;
#[cfg(feature = "jubjub")]
mod tjubjub;
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
