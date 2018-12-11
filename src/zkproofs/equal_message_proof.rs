/*
    zk-paillier

    Copyright 2018 by Kzen Networks

    This file is part of Multisig Schnorr library
    (https://github.com/KZen-networks/multisig-schnorr)

    Multisig Schnorr is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/zk-paillier/blob/master/LICENSE>
*/
use curv::arithmetic::traits::Samplable;
use curv::BigInt;
use paillier::arithimpl::traits::ModMul;
use paillier::arithimpl::traits::ModPow;
use paillier::traits::{Add, Mul};
use paillier::{
    EncryptWithChosenRandomness, EncryptionKey, Paillier, Randomness, RawCiphertext, RawPlaintext,
};
use std::error::Error;
use std::fmt;
/// Zero-knowledge proof for encryption of same value under two different keys
///
/*
Statement is C1, C2. Prover wants to prove knowledge of x,r1,r2 such that
C1 = (1+N1)^x *r1^N1 mod N1^2 and C2 = (1+N2)^x *r2^N2 mod N2^2:

prover first message: choose alpha, r3, r4, where 0<= alpha < min(N1,N2), 0<r3< N1, 0<r4< N2 compute:
D1= (1+N1)^alpha *r3^N1 mod N1^2 and D2 = (1+N2)^alpha *r4^N2 mod N2^2,
send D1,D2

verifier sends a random challenge e

prover computes: z = alpha + ex, s1 = r3r1^e mod N1, s2 = r4r2^e mod N2
sends z,s1,s2

verifier checks:
Enc_N1(z1 mod N1, s1) = C1^e*D1
Enc_N2(z1 mod N2, s2) = C2^e*D2

The above protocol works for |alpha| >> |ex|


*/
///
/// This is a non-interactive version of the proof, using Fiat Shamir Transform and assuming Random Oracle Model

#[derive(Debug)]
pub struct ProofError;

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ProofError")
    }
}

impl Error for ProofError {
    fn description(&self) -> &str {
        " proof error"
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct Challenge {
    pub e: Vec<u8>,
}

#[derive(Clone, PartialEq, Debug)]
pub struct Statement<'a> {
    pub c1: RawCiphertext<'a>,
    pub ek1: EncryptionKey,
    pub c2: RawCiphertext<'a>,
    pub ek2: EncryptionKey,
}

#[derive(PartialEq, Debug)]
pub struct Witness<'a> {
    pub x: RawPlaintext<'a>,
    pub r1: Randomness,
    pub r2: Randomness,
}

#[derive(PartialEq, Debug)]
pub struct Proof<'a> {
    d1: RawCiphertext<'a>,
    d2: RawCiphertext<'a>,
    z1: BigInt,
    s1: Randomness,
    s2: Randomness,
}

pub trait NISigmaProof<T, W, S> {
    fn prove(w: &W, delta: &S) -> T;

    fn verify(&self, delta: &S) -> Result<(), ProofError>;
}

impl<'a> NISigmaProof<Proof<'a>, Witness<'a>, Statement<'a>> for Proof<'a> {
    fn prove(w: &Witness, delta: &Statement) -> Proof<'a> {
        let r3 = BigInt::sample_below(&delta.ek1.n);
        let r4 = BigInt::sample_below(&delta.ek2.n);
        let min_n = BigInt::min(delta.ek1.n.clone(), delta.ek2.n.clone());
        let alpha = BigInt::sample_below(&min_n);
        let d1 = Paillier::encrypt_with_chosen_randomness(
            &delta.ek1,
            RawPlaintext::from(&alpha),
            &Randomness::from(r3.clone()),
        );
        let d2 = Paillier::encrypt_with_chosen_randomness(
            &delta.ek2,
            RawPlaintext::from(&alpha),
            &Randomness::from(r4.clone()),
        );
        let mut vec: Vec<BigInt> = Vec::new();
        vec.push(delta.ek1.n.clone());
        vec.push(delta.ek2.n.clone());
        vec.push(delta.c1.0.clone().into_owned());
        vec.push(delta.c2.0.clone().into_owned());
        vec.push(d1.0.clone().into_owned());
        vec.push(d2.0.clone().into_owned());
        let hash_digest = super::compute_digest(vec.iter());
        let e_bn = BigInt::from(&hash_digest[..]);
        // let ex = ModMul::modmul(&e_bn, &w.x.0, &min_n);
        let z1 = alpha + &e_bn * &w.x.0.clone().into_owned();
        let r1_e = BigInt::modpow(&w.r1.0, &e_bn, &delta.ek1.n);
        let r2_e = BigInt::modpow(&w.r2.0, &e_bn, &delta.ek2.n);
        let s1 = BigInt::modmul(&r3, &r1_e, &delta.ek1.n);
        let s2 = BigInt::modmul(&r4, &r2_e, &delta.ek2.n);
        Proof {
            d1,
            d2,
            z1,
            s1: Randomness::from(s1),
            s2: Randomness::from(s2),
        }
    }

    fn verify(&self, delta: &Statement) -> Result<(), ProofError> {
        let mut vec: Vec<BigInt> = Vec::new();
        vec.push(delta.ek1.n.clone());
        vec.push(delta.ek2.n.clone());
        vec.push(delta.c1.0.clone().into_owned());
        vec.push(delta.c2.0.clone().into_owned());
        vec.push(self.d1.0.clone().into_owned());
        vec.push(self.d2.0.clone().into_owned());
        let digest = super::compute_digest(vec.iter());
        let e_bn = BigInt::from(&digest[..]);
        let enc_n1 = Paillier::encrypt_with_chosen_randomness(
            &delta.ek1,
            RawPlaintext::from(self.z1.clone() % delta.ek1.n.clone()),
            &self.s1,
        );
        let enc_n2 = Paillier::encrypt_with_chosen_randomness(
            &delta.ek2,
            RawPlaintext::from(self.z1.clone() % delta.ek2.n.clone()),
            &self.s2,
        );
        let c1_e = Paillier::mul(
            &delta.ek1,
            delta.c1.clone(),
            RawPlaintext::from(&e_bn).clone(),
        );
        let c2_e = Paillier::mul(
            &delta.ek2,
            delta.c2.clone(),
            RawPlaintext::from(&e_bn).clone(),
        );
        let d1_c1_e = Paillier::add(&delta.ek1, c1_e, self.d1.clone());
        let d2_c2_e = Paillier::add(&delta.ek2, c2_e, self.d2.clone());

        if d1_c1_e == enc_n1 && d2_c2_e == enc_n2 {
            Ok(())
        } else {
            Err(ProofError)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curv::BigInt;
    use paillier::EncryptWithChosenRandomness;
    use paillier::KeyGeneration;

    #[test]
    fn test_equal_message_zk_proof() {
        let (ek1, _dk1) = Paillier::keypair().keys();
        let (ek2, _dk2) = Paillier::keypair().keys();
        let min_n = BigInt::min(ek1.n.clone(), ek2.n.clone());
        let x = BigInt::sample_below(&min_n);
        let r1 = BigInt::sample_below(&ek1.n);
        let r2 = BigInt::sample_below(&ek2.n);
        let w = Witness {
            x: RawPlaintext::from(&x),
            r1: Randomness::from(&r1),
            r2: Randomness::from(&r2),
        };
        let c1 = Paillier::encrypt_with_chosen_randomness(
            &ek1,
            RawPlaintext::from(&x),
            &Randomness::from(r1),
        );
        let c2 = Paillier::encrypt_with_chosen_randomness(
            &ek2,
            RawPlaintext::from(&x),
            &Randomness::from(r2),
        );
        let delta = Statement { c1, ek1, c2, ek2 };
        let proof = Proof::prove(&w, &delta);
        assert!(proof.verify(&delta).is_ok());
    }
}
