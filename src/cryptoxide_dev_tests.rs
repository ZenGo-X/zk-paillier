
#[cfg(test)]
mod tests {
    use ring::digest::{Context, SHA256};
    use ring::{hmac, test};

    use std::borrow::Borrow;

    use curv::BigInt;

    const SHA256_SIGNATURE_RESULT_FORMATED_STRING: &str =
        "Signature(SHA256:3c1042fecc7664f666bd94bb1e8ea1211413dc44c4967c92f65619acfc5598c4)";
    const EXAMPLE_STRING: &str = "hello, world";
    const EXPECTED_HEX: &str = "09ca7e4eaa6e8ae9c7d261167129184883644d07dfba7cbfbc4c8a2e08360d5b";

    /// single shot method using ring to replace
    fn compute_digest(bytes: &[u8]) -> BigInt {
        let mut digest = Context::new(&SHA256);
        digest.update(&bytes);
        BigInt::from(digest.finish().as_ref())
    }

    /// single shot method replacing ring with cryptoxide
    fn compute_digest_replace(bytes: &[u8]) -> BigInt {
        use cryptoxide::digest::Digest;
        use cryptoxide::sha2::Sha256;
        use std::iter::repeat;

        // create a SHA3-256 object
        let mut hasher = Sha256::new();

        // write input message
        hasher.input(bytes);

        let mut vect_result: Vec<u8> = repeat(0u8).take(32).collect(); //TODO: need some sane way of creating &mut [u8]
        hasher.result(&mut vect_result);
        BigInt::from(vect_result.as_ref())
    }

    /// multipart method method using ring to replace
    fn compute_digest_multipart<IT>(values: IT) -> Vec<u8>
    where
        IT: Iterator,
        IT::Item: Borrow<BigInt>,
    {
        let mut digest = Context::new(&SHA256);
        for value in values {
            let bytes: Vec<u8> = value.borrow().into();
            digest.update(&bytes);
        }
        digest.finish().as_ref().into()
    }

    /// multipart method replacing ring with cryptoxide
    fn compute_digest_multipart_replace<IT>(values: IT) -> Vec<u8>
    where
        IT: Iterator,
        IT::Item: Borrow<BigInt>,
    {
        use cryptoxide::digest::Digest;
        use cryptoxide::sha2::Sha256;
        use std::iter::repeat;

        // create a SHA3-256 object
        let mut hasher = Sha256::new();

        let mut flatten_array: Vec<u8> = Vec::new();
        for value in values {
            let bytes: Vec<u8> = value.borrow().into();
            //hasher.update(&bytes);
            flatten_array.extend_from_slice(&bytes);
        }

        // alternative way of merging iter
        // let flatten_array: Vec<u8> = values
        //                 //.iter()
        //                 .flat_map(|array| array.borrow().into())
        //                 .cloned()
        //                 .collect();

        //digest.finish().as_ref().into()


        hasher.input(&flatten_array);
        let mut vect_result: Vec<u8> = repeat(0u8).take(32).collect(); //TODO: need some sane way of creating &mut [u8]
        hasher.result(&mut vect_result);
        return vect_result;
    }

    //tests

    #[test]
    fn test_cryptoxide_nomod() {
        use cryptoxide::digest::Digest;
        use cryptoxide::sha3::Sha3;

        // create a SHA3-256 object
        let mut hasher = Sha3::sha3_256();

        // write input message
        hasher.input_str("abc");

        // read hash digest
        let hex = hasher.result_str();

        assert_eq!(
            hex,
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
    }

    #[test]
    fn test_cryptoxide_nomod_byte_res() {
        use cryptoxide::digest::Digest;
        use cryptoxide::sha2::Sha256;
        use std::iter::repeat;

        // create a SHA3-256 object
        let mut hasher = Sha256::new();

        // write input message
        hasher.input(EXAMPLE_STRING.as_bytes());

        let expected: Vec<u8> = test::from_hex(EXPECTED_HEX).unwrap();

        let result_str = hasher.result_str();
        assert_eq!(result_str, EXPECTED_HEX);

        let mut result: Vec<u8> = repeat(0u8).take(32).collect(); //TODO: need some sane way of creating &mut [u8]
        hasher.result(&mut result);
        let result_bigint = BigInt::from(result.as_ref());

        assert_eq!(result, expected);

        assert_eq!(result_bigint, BigInt::from(expected.as_ref()));
    }

    #[test]
    fn hmac_debug() {
        let key = hmac::SigningKey::new(&SHA256, &[0; 32]);
        assert_eq!("SHA256", format!("{:?}", &key));

        let ctx = hmac::SigningContext::with_key(&key);
        assert_eq!("SHA256", format!("{:?}", &ctx));
    }

    #[test]
    fn ring_singleshot_test() {
        // The sender generates a secure key value and signs the message with it.
        // Note that in a real protocol, a key agreement protocol would be used to
        // derive `key_value`.
        let //mut 
            key_value = [0u8; 32];

        //randomization disabled
        //let rng = rand::SystemRandom::new();
        //rng.fill(&mut key_value);

        let s_key = hmac::SigningKey::new(&SHA256, key_value.as_ref());
        let signature = hmac::sign(&s_key, EXAMPLE_STRING.as_bytes());

        // The receiver (somehow!) knows the key value, and uses it to verify the
        // integrity of the message.

        //let v_key = hmac::VerificationKey::new(&SHA256, key_value.as_ref());
        //hmac::verify(&v_key, EXAMPLE_STRING.as_bytes(), signature.as_ref());
        assert_eq!(
            SHA256_SIGNATURE_RESULT_FORMATED_STRING,
            format!("{:?}", &signature)
        );
    }

    #[test]
    fn test_cryptoxide_replace() {
        use cryptoxide::digest::Digest;
        use cryptoxide::sha2::Sha256;
        use std::iter::repeat;

        // create a SHA3-256 object
        let mut hasher = Sha256::new();

        // write input message
        hasher.input_str(&EXAMPLE_STRING);

        // read hash digest
        let hex = hasher.result_str();

        assert_eq!(hex, EXPECTED_HEX);

        use ring::digest;

        let one_shot = digest::digest(&digest::SHA256, EXAMPLE_STRING.as_bytes());

        let expected: Vec<u8> = test::from_hex(EXPECTED_HEX).unwrap();
        let actual = digest::digest(&digest::SHA256, EXAMPLE_STRING.as_bytes());

        assert_eq!(&expected, &actual.as_ref());

        let mut ctx = digest::Context::new(&digest::SHA256);
        ctx.update(b"hello");
        ctx.update(b", ");
        ctx.update(b"world");
        let multi_part = ctx.finish();

        let one_shot_res = one_shot.as_ref();
        let mut buf_crtxd_res: Vec<u8> = repeat(0u8).take(32).collect(); //TODO: need some sane way of creating &mut [u8]
        hasher.result(&mut buf_crtxd_res);

        assert_eq!(&one_shot_res, &multi_part.as_ref());
        assert_eq!(buf_crtxd_res, one_shot_res);

        //inline code of compute_digest to test
        let mut digest = Context::new(&SHA256);
        digest.update(EXAMPLE_STRING.as_bytes());
        let dgst_finish = digest.finish();
        let ring_dgst_ref = dgst_finish.as_ref();
        let ring_dgst_bigint = BigInt::from(ring_dgst_ref);

        assert_eq!(ring_dgst_ref, one_shot_res);

        let cmpt_dgst_res = compute_digest(EXAMPLE_STRING.as_bytes());
        assert_eq!(
            format!("{:?}", &cmpt_dgst_res),
            format!("{:?}", BigInt::from(one_shot_res))
        );
        assert_eq!(
            format!("{:?}", &cmpt_dgst_res),
            format!("{:?}", ring_dgst_bigint)
        );

        let cmpt_dgst_res_replaced = compute_digest_replace(EXAMPLE_STRING.as_bytes());
        assert_eq!(
            format!("{:?}", &cmpt_dgst_res_replaced),
            format!("{:?}", BigInt::from(one_shot_res))
        );
        assert_eq!(
            format!("{:?}", &cmpt_dgst_res_replaced),
            format!("{:?}", ring_dgst_bigint)
        );

        //multipart test
        let words = [
            BigInt::from("hello".as_bytes()),
            BigInt::from(", ".as_bytes()),
            BigInt::from("world".as_bytes()),
        ];
        let exmpl_str_iter = words.iter();
        let cmpt_dgst_m = compute_digest_multipart(exmpl_str_iter);
        assert_eq!(
            format!("{:?}", BigInt::from(cmpt_dgst_m.as_ref())),
            format!("{:?}", ring_dgst_bigint)
        );

        let exmpl_str_iter2 = words.iter();
        let cmpt_dgst_m_r = compute_digest_multipart_replace(exmpl_str_iter2);
        assert_eq!(
            format!("{:?}", BigInt::from(cmpt_dgst_m_r.as_ref())),
            format!("{:?}", ring_dgst_bigint)
        );
    }

    #[test]
    fn ring_multipart_test() {
        let parts = ["hello", ", ", "world"];
        // The sender generates a secure key value and signs the message with it.
        // Note that in a real protocol, a key agreement protocol would be used to
        // derive `key_value`.
        let //mut 
            key_value = [0u8; 32];
        // let rng = rand::SystemRandom::new();
        // rng.fill(&mut key_value)?;
        let s_key = hmac::SigningKey::new(&SHA256, key_value.as_ref());
        let mut s_ctx = hmac::SigningContext::with_key(&s_key);
        for part in &parts {
            s_ctx.update(part.as_bytes());
        }
        let signature = s_ctx.sign();
        // The receiver (somehow!) knows the key value, and uses it to verify the
        // integrity of the message.
        //let v_key = hmac::VerificationKey::new(&SHA256, key_value.as_ref());
        let mut msg = Vec::<u8>::new();
        for part in &parts {
            msg.extend(part.as_bytes());
        }

        assert_eq!(
            SHA256_SIGNATURE_RESULT_FORMATED_STRING,
            format!("{:?}", &signature)
        );
    }
}


// some code based on example of ring 0.13.5

// Copyright 2015-2016 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
