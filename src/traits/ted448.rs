use super::*;
use ed448_goldilocks_plus::Scalar;
use elliptic_curve::hash2curve::ExpandMsgXof;

impl ScalarHash for Scalar {
    fn hash_to_scalar(bytes: &[u8]) -> Self {
        Scalar::hash::<ExpandMsgXof<sha3::Shake256>>(bytes, b"edwards448_XOF:SHAKE256_RO_NUL_")
    }
}
