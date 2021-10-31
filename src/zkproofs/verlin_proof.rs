use std::iter;

use serde::{Deserialize, Serialize};

use curv::arithmetic::traits::*;
use curv::BigInt;
use paillier::traits::{Add, Mul};
use paillier::EncryptWithChosenRandomness;
use paillier::Paillier;
use paillier::{EncryptionKey, Randomness, RawCiphertext, RawPlaintext};

use super::errors::IncorrectProof;

/// A sigma protocol to allow a prover to demonstrate that a ciphertext c_x has been computed using
/// two other ciphertexts c_cprime, as well as a known value.
///
/// The proof is taken from https://eprint.iacr.org/2011/494.pdf 3.3.1
///
/// Witness: {x,x_prime, x_double_prime, r_x}
///
/// Statement: {c_x, c, c_prime}.
///
/// The relation is such that:
/// phi_x = c^x * c_prime^x_prime * Enc(x_double_prime, r_x)
///
/// The protocol:
///
/// 1. Prover picks random: a,a_prime,a_double_prime and r_a and computes: phi_a
/// 2. prover computes a challenge e using Fiat-Shamir
/// 3. Prover computes z = xe + a, z' = x'e + a', z_double_prime = x_double_prime*e + a_double_prime
///    and r_z = r_x^e*r_a
///
/// Verifier accepts if phi_z = phi_x^e * phi_a
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct VerlinProof {
    pub phi_a: BigInt,
    pub z: BigInt,
    pub z_prime: BigInt,
    pub z_double_prime: BigInt,
    pub r_z: BigInt,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct VerlinWitness {
    pub x: BigInt,
    pub x_prime: BigInt,
    pub x_double_prime: BigInt,
    pub r_x: BigInt,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct VerlinStatement {
    pub ek: EncryptionKey,
    pub c: BigInt,
    pub c_prime: BigInt,
    pub phi_x: BigInt,
}

impl VerlinProof {
    pub fn prove(witness: &VerlinWitness, statement: &VerlinStatement) -> Self {
        let a = BigInt::sample_below(&statement.ek.n);
        let a_prime = BigInt::sample_below(&statement.ek.n);
        let a_double_prime = BigInt::sample_below(&statement.ek.n);
        let mut r_a = BigInt::sample_below(&statement.ek.n);
        while BigInt::gcd(&r_a, &statement.ek.n) != BigInt::one() {
            r_a = BigInt::sample_below(&statement.ek.n);
        }

        let phi_a = gen_phi(
            &statement.ek,
            &statement.c,
            &statement.c_prime,
            &a,
            &a_prime,
            &a_double_prime,
            &r_a,
        );

        let e = super::compute_digest(
            iter::once(&statement.ek.n)
                .chain(iter::once(&statement.c))
                .chain(iter::once(&statement.c_prime))
                .chain(iter::once(&statement.phi_x))
                .chain(iter::once(&phi_a)),
        );
        let z = &witness.x * &e + &a;
        let z_prime = &witness.x_prime * &e + &a_prime;
        let z_double_prime = &witness.x_double_prime * &e + &a_double_prime;
        let r_x_e = BigInt::mod_pow(&witness.r_x, &e, &statement.ek.nn);
        let r_z = BigInt::mod_mul(&r_x_e, &r_a, &statement.ek.nn);

        VerlinProof {
            phi_a,
            z,
            z_prime,
            z_double_prime,
            r_z,
        }
    }

    pub fn verify(&self, statement: &VerlinStatement) -> Result<(), IncorrectProof> {
        let e = super::compute_digest(
            iter::once(&statement.ek.n)
                .chain(iter::once(&statement.c))
                .chain(iter::once(&statement.c_prime))
                .chain(iter::once(&statement.phi_x))
                .chain(iter::once(&self.phi_a)),
        );
        let phi_x_e = Paillier::mul(
            &statement.ek,
            RawCiphertext::from(statement.phi_x.clone()),
            RawPlaintext::from(e),
        );
        let phi_x_e_phi_a = Paillier::add(
            &statement.ek,
            phi_x_e,
            RawCiphertext::from(self.phi_a.clone()),
        );

        let phi_z = gen_phi(
            &statement.ek,
            &statement.c,
            &statement.c_prime,
            &self.z,
            &self.z_prime,
            &self.z_double_prime,
            &self.r_z,
        );

        match phi_z == phi_x_e_phi_a.0.into_owned() {
            true => Ok(()),
            false => Err(IncorrectProof),
        }
    }
}

// helper
fn gen_phi(
    ek: &EncryptionKey,
    c: &BigInt,
    c_prime: &BigInt,
    y: &BigInt,
    y_prime: &BigInt,
    y_double_prime: &BigInt,
    r_y: &BigInt,
) -> BigInt {
    let c_y = Paillier::mul(
        ek,
        RawCiphertext::from(c.clone()),
        RawPlaintext::from(y.clone()),
    );
    let c_prime_y_prime = Paillier::mul(
        ek,
        RawCiphertext::from(c_prime.clone()),
        RawPlaintext::from(y_prime.clone()),
    );
    let c_y_double_prime_r_y = Paillier::encrypt_with_chosen_randomness(
        ek,
        RawPlaintext::from(y_double_prime.clone()),
        &Randomness(r_y.clone()),
    );
    let c_y_c_prime_y_prime = Paillier::add(ek, c_y, c_prime_y_prime);
    let phi_y = Paillier::add(ek, c_y_c_prime_y_prime, c_y_double_prime_r_y);
    phi_y.0.into_owned()
}

#[cfg(test)]
mod tests {
    use curv::arithmetic::traits::*;
    use curv::BigInt;
    use paillier::traits::Encrypt;
    use paillier::traits::KeyGeneration;
    use paillier::Paillier;
    use paillier::RawPlaintext;

    use crate::zkproofs::verlin_proof::gen_phi;
    use crate::zkproofs::verlin_proof::VerlinProof;
    use crate::zkproofs::verlin_proof::VerlinStatement;
    use crate::zkproofs::verlin_proof::VerlinWitness;

    #[test]
    fn test_verlin_proof() {
        let (ek, _) = Paillier::keypair().keys();
        let x = BigInt::sample_below(&ek.n);
        let x_prime = BigInt::sample_below(&ek.n);
        let x_double_prime = BigInt::sample_below(&ek.n);
        let mut r_x = BigInt::sample_below(&ek.n);
        while BigInt::gcd(&r_x, &ek.n) != BigInt::one() {
            r_x = BigInt::sample_below(&ek.n);
        }

        let c = Paillier::encrypt(&ek, RawPlaintext::from(x.clone()));
        let c_bn = c.0.clone().into_owned();
        let c_prime = Paillier::encrypt(&ek, RawPlaintext::from(x_prime.clone()));
        let c_prime_bn = c_prime.0.clone().into_owned();
        let phi_x = gen_phi(&ek, &c_bn, &c_prime_bn, &x, &x_prime, &x_double_prime, &r_x);

        let witness = VerlinWitness {
            x,
            x_prime,
            x_double_prime,
            r_x,
        };

        let statement = VerlinStatement {
            ek,
            c: c_bn,
            c_prime: c_prime_bn,
            phi_x,
        };

        let proof = VerlinProof::prove(&witness, &statement);
        let verify = proof.verify(&statement);
        assert!(verify.is_ok());
    }

    #[test]
    #[should_panic]
    fn test_bad_verlin_proof() {
        let (ek, _) = Paillier::keypair().keys();
        let x = BigInt::sample_below(&ek.n);
        let x_prime = BigInt::sample_below(&ek.n);
        let x_double_prime = BigInt::sample_below(&ek.n);
        let mut r_x = BigInt::sample_below(&ek.n);
        while BigInt::gcd(&r_x, &ek.n) != BigInt::one() {
            r_x = BigInt::sample_below(&ek.n);
        }

        let c = Paillier::encrypt(&ek, RawPlaintext::from(x.clone()));
        let c_bn = c.0.clone().into_owned();
        let c_prime = Paillier::encrypt(&ek, RawPlaintext::from(x_prime.clone()));
        let c_prime_bn = c_prime.0.clone().into_owned();
        // we inject x_bad = 2x
        let phi_x = gen_phi(
            &ek,
            &c_bn,
            &c_prime_bn,
            &(&x * BigInt::from(2)),
            &x_prime,
            &x_double_prime,
            &r_x,
        );

        let witness = VerlinWitness {
            x,
            x_prime,
            x_double_prime,
            r_x,
        };

        let statement = VerlinStatement {
            ek,
            c: c_bn,
            c_prime: c_prime_bn,
            phi_x,
        };

        let proof = VerlinProof::prove(&witness, &statement);
        let verify = proof.verify(&statement);
        assert!(verify.is_ok());
    }

    #[test]
    #[should_panic]
    fn test_bad_verlin_proof_2() {
        let (ek, _) = Paillier::keypair().keys();
        let x = BigInt::sample_below(&ek.n);
        let x_prime = BigInt::sample_below(&ek.n);
        let x_double_prime = BigInt::sample_below(&ek.n);
        let mut r_x = BigInt::sample_below(&ek.n);
        while BigInt::gcd(&r_x, &ek.n) != BigInt::one() {
            r_x = BigInt::sample_below(&ek.n);
        }

        let c = Paillier::encrypt(&ek, RawPlaintext::from(x.clone()));
        let c_bn = c.0.clone().into_owned();
        let c_prime = Paillier::encrypt(&ek, RawPlaintext::from(x_prime.clone()));
        let c_prime_bn = c_prime.0.clone().into_owned();
        // we inject r_x_bad = r_x + 1
        let phi_x = gen_phi(
            &ek,
            &c_bn,
            &c_prime_bn,
            &(&x * BigInt::from(2)),
            &x_prime,
            &x_double_prime,
            &(&r_x + BigInt::one()),
        );

        let witness = VerlinWitness {
            x,
            x_prime,
            x_double_prime,
            r_x,
        };

        let statement = VerlinStatement {
            ek,
            c: c_bn,
            c_prime: c_prime_bn,
            phi_x,
        };

        let proof = VerlinProof::prove(&witness, &statement);
        let verify = proof.verify(&statement);
        assert!(verify.is_ok());
    }
}
