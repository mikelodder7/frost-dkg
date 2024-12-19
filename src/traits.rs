use elliptic_curve::PrimeField;

/// A trait for hashing a scalar
pub trait ScalarHash: PrimeField {
    /// Hash a scalar
    fn hash_to_scalar(bytes: &[u8]) -> Self;
}
