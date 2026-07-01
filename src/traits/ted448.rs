use super::*;
use ed448_goldilocks_plus::Scalar;
use hash2curve::ExpandMsgXof;

impl ScalarHash for Scalar {
    fn hash_to_scalar(bytes: &[u8]) -> Self {
        Scalar::hash::<ExpandMsgXof<shake::Shake256>>(bytes, b"edwards448_XOF:SHAKE256_RO_NUL_")
    }
}
