use super::*;
use elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use p384::{NistP384, Scalar};

impl ScalarHash for Scalar {
    fn hash_to_scalar(bytes: &[u8]) -> Self {
        const DST: &[u8] = b"P384_XMD:SHA-384_RO_NUL_";
        <NistP384 as GroupDigest>::hash_to_scalar::<ExpandMsgXmd<sha2::Sha384>>(&[bytes], &[DST])
            .expect("hash_to_scalar failed")
    }
}
