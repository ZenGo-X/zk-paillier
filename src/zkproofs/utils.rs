use std::borrow::Borrow;

use curv::arithmetic::traits::*;
use curv::BigInt;

use digest::Digest;
use sha2::Sha256;

pub fn compute_digest<IT>(it: IT) -> BigInt
where
    IT: Iterator,
    IT::Item: Borrow<BigInt>,
{
    let mut hasher = Sha256::new();
    for value in it {
        let bytes: Vec<u8> = value.borrow().to_bytes();
        hasher.input(&bytes);
    }

    let result_bytes = hasher.result();
    BigInt::from_bytes(&result_bytes[..])
}
