/*
    zk-paillier

    Copyright 2018 by Kzen Networks

    This file is part of Multisig Schnorr library
    (https://github.com/KZen-networks/multisig-schnorr)

    zk-paillier is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/zk-paillier/blob/master/LICENSE>
*/
use std::borrow::Borrow;
use std::error::Error;
use std::fmt;
use std::iter;

use curv::arithmetic::traits::*;
use curv::BigInt;
use paillier::{extract_nroot, DecryptionKey, EncryptionKey};
use rayon::prelude::*;
//use ring::digest::{Context, SHA256};
use cryptoxide::digest::Digest;
use cryptoxide::sha2::Sha256;

const STATISTICAL_ERROR_FACTOR: usize = 40;

// TODO: generalize the error string and move the struct to a common location where all other proofs can use it as well
// TODO[Morten]: better: use error chain!
#[derive(Debug)]
pub struct CorrectKeyProofError;

impl fmt::Display for CorrectKeyProofError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ProofError")
    }
}

impl Error for CorrectKeyProofError {
    fn description(&self) -> &str {
        "Error while verifying"
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Challenge {
    #[serde(with = "::serialize::vecbigint")]
    pub sn: Vec<BigInt>,

    #[serde(with = "::serialize::bigint")]
    pub e: BigInt,

    #[serde(with = "::serialize::vecbigint")]
    pub z: Vec<BigInt>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerificationAid {
    #[serde(with = "::serialize::bigint")]
    s_digest: BigInt,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CorrectKeyProof {
    #[serde(with = "::serialize::bigint")]
    s_digest: BigInt,
}

/// Zero-knowledge proof of co-primality between the encryption modulus and its order.
///
/// The sub-protocol for proving knowledge of challenge plaintexts is made non-interactive
/// using the [Fiat-Shamir heuristic](https://en.wikipedia.org/wiki/Fiat%E2%80%93Shamir_heuristic).
///
/// References:
/// - section 3.1 in [Lindell'17](https://eprint.iacr.org/2017/552)
/// - section 3.3 in [HMRTN'12](https://eprint.iacr.org/2011/494)
/// - section 4.2 in [DJ'01](http://www.brics.dk/RS/00/45/BRICS-RS-00-45.pdf)
pub trait CorrectKeyTrait<EK, DK> {
    /// Generate challenge for given encryption key.
    fn challenge(ek: &EK) -> (Challenge, VerificationAid);

    /// Generate proof given decryption key.
    fn prove(dk: &DK, challenge: &Challenge) -> Result<CorrectKeyProof, CorrectKeyProofError>;

    /// Verify proof.
    fn verify(proof: &CorrectKeyProof, aid: &VerificationAid) -> Result<(), CorrectKeyProofError>;
}

pub struct CorrectKey;
impl CorrectKeyTrait<EncryptionKey, DecryptionKey> for CorrectKey {
    fn challenge(ek: &EncryptionKey) -> (Challenge, VerificationAid) {
        // Compute challenges in the form of n-powers

        let s: Vec<_> = (0..STATISTICAL_ERROR_FACTOR)
            .into_par_iter()
            .map(|_| BigInt::sample_below(&ek.n))
            .collect();

        let sn: Vec<_> = s
            .par_iter()
            .map(|si| BigInt::mod_pow(si, &ek.n, &ek.n))
            .collect();

        // Compute non-interactive proof of knowledge of the n-roots in the above
        // TODO[Morten] introduce new proof type for this that can be used independently?

        let r: Vec<_> = (0..STATISTICAL_ERROR_FACTOR)
            .into_par_iter()
            .map(|_| BigInt::sample_below(&ek.n))
            .collect();

        let rn: Vec<_> = r
            .par_iter()
            .map(|ri| BigInt::mod_pow(ri, &ek.n, &ek.n))
            .collect();

        let e = compute_digest(iter::once(&ek.n).chain(&sn).chain(&rn));

        let z: Vec<_> = r
            .par_iter()
            .zip(s.par_iter())
            .map(|(ri, si)| (ri * BigInt::mod_pow(si, &e, &ek.n)) % &ek.n)
            .collect();

        // Compute expected result for equality test in verification
        let s_digest: BigInt = compute_digest(s.iter());

        (Challenge { sn, e, z }, VerificationAid { s_digest })
    }

    fn prove(
        dk: &DecryptionKey,
        challenge: &Challenge,
    ) -> Result<CorrectKeyProof, CorrectKeyProofError> {
        let mut fail = false; // !!! Do not change
        let dk_n = &dk.q * &dk.p;
        // check sn co-prime with n
        fail = challenge
            .sn
            .par_iter()
            .any(|sni| BigInt::egcd(&dk_n, sni).0 != BigInt::one())
            || fail;

        // check z co-prime with n
        fail = challenge
            .z
            .par_iter()
            .any(|zi| BigInt::egcd(&dk_n, zi).0 != BigInt::one())
            || fail;

        // reconstruct rn
        let phi = (dk.q.clone() - 1) * (dk.p.clone() - 1);
        // TODO: make dk.phi public
        let phimine = &phi - (&challenge.e % &phi);
        let rn: Vec<_> = challenge
            .z
            .par_iter()
            .zip(challenge.sn.par_iter())
            .map(|(zi, sni)| {
                let zn = BigInt::mod_pow(zi, &dk_n, &dk_n);
                let snphi = BigInt::mod_pow(sni, &phimine, &dk_n);
                (zn * snphi) % &dk_n
            })
            .collect();

        // check rn co-prime with n
        fail = rn
            .par_iter()
            .any(|rni| BigInt::egcd(&dk_n, rni).0 != BigInt::one())
            || fail;

        // check that e was computed correctly
        let e = compute_digest(iter::once(&dk_n).chain(&challenge.sn).chain(&rn));
        fail = (challenge.e != e) || fail;

        if fail {
            return Err(CorrectKeyProofError);
        }

        // compute proof in the form of a hash of the recovered roots
        let s_digest = compute_digest(challenge.sn.iter().map(|sni| {
            let si = extract_nroot(dk, sni);
            si
        }));

        Ok(CorrectKeyProof { s_digest })
    }

    fn verify(proof: &CorrectKeyProof, va: &VerificationAid) -> Result<(), CorrectKeyProofError> {
        // compare actual with expected
        if proof.s_digest == va.s_digest {
            Ok(())
        } else {
            Err(CorrectKeyProofError)
        }
    }
}

// TODO[Morten] generalise and move to super
pub fn compute_digest<IT>(values: IT) -> BigInt
where
    IT: Iterator,
    IT::Item: Borrow<BigInt>,
{
    /*
    let mut digest = Context::new(&SHA256);
    for value in values {
        let bytes: Vec<u8> = value.borrow().into();
        digest.update(&bytes);
    }
    BigInt::from(digest.finish().as_ref())
    */

    let mut hasher = Sha256::new();

    for value in values {
        let bytes: Vec<u8> = value.borrow().into();
        hasher.input(&bytes);
    }

    let mut result = [0; 32];
    hasher.result(&mut result);
    BigInt::from(result.as_ref())
}

#[cfg(test)]
mod tests {

    use super::*;
    use paillier::Keypair;

    fn test_keypair() -> Keypair {
        let p = str::parse("148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517").unwrap();
        let q = str::parse("158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463").unwrap();
        Keypair { p, q }
    }

    #[test]
    fn test_correct_zk_proof() {
        let (ek, dk) = test_keypair().keys();

        let (challenge, verification_aid) = CorrectKey::challenge(&ek);
        let proof_results = CorrectKey::prove(&dk, &challenge);
        assert!(proof_results.is_ok());

        let result = CorrectKey::verify(&proof_results.unwrap(), &verification_aid);
        assert!(result.is_ok());
    }

    #[test]
    fn test_incorrect_zk_proof() {
        let (ek, dk) = test_keypair().keys();

        let (mut challenge, _verification_aid) = CorrectKey::challenge(&ek);
        challenge.e += 1;
        let proof_results = CorrectKey::prove(&dk, &challenge);

        assert!(proof_results.is_err()); // ERROR expected because of manipulated challenge
    }

    #[test]
    fn test_incorrect_zk_proof_2() {
        let (ek, dk) = test_keypair().keys();

        let (challenge, mut verification_aid) = CorrectKey::challenge(&ek);
        let proof_results = CorrectKey::prove(&dk, &challenge);
        assert!(proof_results.is_ok());

        verification_aid.s_digest += 1;
        let result = CorrectKey::verify(&proof_results.unwrap(), &verification_aid);
        assert!(result.is_err()); // ERROR expected because of manipulated aid
    }

}
