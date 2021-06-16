use std::iter;

use serde::{Deserialize, Serialize};

use curv::arithmetic::traits::*;
use curv::BigInt;
use paillier::traits::{Add, Mul};
use paillier::EncryptWithChosenRandomness;
use paillier::Paillier;
use paillier::{EncryptionKey, Randomness, RawCiphertext, RawPlaintext};

use super::errors::IncorrectProof;

/// The proof allows a prover to prove that a ciphertext is an encryption of zero.
///
/// It is taken from DJ01 [https://www.brics.dk/RS/00/45/BRICS-RS-00-45.pdf]
/// protocol for n^s power for s=1.
///
/// Both P and V know a ciphertext c. P knows randomness r such that c= r^n mod n^2
///
/// The protocol:
///
/// 1. P chooses a random r' and computes a = r'^n mod n^2
/// 2. P computes z = r'*r^e mod n^2 (e is the verifier challenge)
/// 3. V checks that z^n = a*c^e mod n^2
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ZeroProof {
    pub z: BigInt,
    pub a: BigInt,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ZeroWitness {
    pub r: BigInt,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ZeroStatement {
    pub ek: EncryptionKey,
    pub c: BigInt,
}

impl ZeroProof {
    pub fn prove(witness: &ZeroWitness, statement: &ZeroStatement) -> Self {
        let r_prime = BigInt::sample_below(&statement.ek.n);
        let a = Paillier::encrypt_with_chosen_randomness(
            &statement.ek,
            RawPlaintext::from(BigInt::zero()),
            &Randomness(r_prime.clone()),
        )
        .0
        .into_owned();

        let e = super::compute_digest(
            iter::once(&statement.ek.n)
                .chain(iter::once(&statement.c))
                .chain(iter::once(&a)),
        );

        let r_e = BigInt::mod_pow(&witness.r, &e, &statement.ek.nn);
        let z = BigInt::mod_mul(&r_prime, &r_e, &statement.ek.nn);

        ZeroProof { z, a }
    }

    pub fn verify(&self, statement: &ZeroStatement) -> Result<(), IncorrectProof> {
        let e = super::compute_digest(
            iter::once(&statement.ek.n)
                .chain(iter::once(&statement.c))
                .chain(iter::once(&self.a)),
        );

        let c_z = Paillier::encrypt_with_chosen_randomness(
            &statement.ek,
            RawPlaintext::from(BigInt::zero()),
            &Randomness(self.z.clone()),
        )
        .0
        .into_owned();

        let c_e = Paillier::mul(
            &statement.ek,
            RawPlaintext::from(e),
            RawCiphertext::from(statement.c.clone()),
        );
        let c_z_test = Paillier::add(&statement.ek, c_e, RawCiphertext::from(self.a.clone()))
            .0
            .into_owned();

        match c_z == c_z_test {
            true => Ok(()),
            false => Err(IncorrectProof),
        }
    }
}

#[cfg(test)]
mod tests {
    use curv::arithmetic::traits::*;
    use curv::BigInt;
    use paillier::core::Randomness;
    use paillier::traits::EncryptWithChosenRandomness;
    use paillier::traits::KeyGeneration;
    use paillier::Paillier;
    use paillier::RawPlaintext;

    use crate::zkproofs::zero_enc_proof::ZeroProof;
    use crate::zkproofs::zero_enc_proof::ZeroStatement;
    use crate::zkproofs::zero_enc_proof::ZeroWitness;

    #[test]
    fn test_zero_proof() {
        let (ek, _) = Paillier::keypair().keys();
        let r = BigInt::sample_below(&ek.n);

        let c = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(BigInt::zero()),
            &Randomness(r.clone()),
        )
        .0
        .into_owned();

        let witness = ZeroWitness { r };

        let statement = ZeroStatement { ek, c };

        let proof = ZeroProof::prove(&witness, &statement);
        let verify = proof.verify(&statement);
        assert!(verify.is_ok());
    }

    #[test]
    #[should_panic]
    fn test_one_proof() {
        let (ek, _) = Paillier::keypair().keys();
        let r = BigInt::sample_below(&ek.n);

        // c encrypts 1
        let c = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(BigInt::one()),
            &Randomness(r.clone()),
        )
        .0
        .into_owned();

        let witness = ZeroWitness { r };

        let statement = ZeroStatement { ek, c };

        let proof = ZeroProof::prove(&witness, &statement);
        let verify = proof.verify(&statement);
        assert!(verify.is_ok());
    }
}
