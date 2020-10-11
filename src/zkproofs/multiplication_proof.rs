use curv::arithmetic::traits::{Modulo, Samplable};
use curv::BigInt;
use paillier::EncryptWithChosenRandomness;
use paillier::Paillier;
use paillier::{EncryptionKey, Randomness, RawPlaintext};
use serde::{Deserialize, Serialize};
use std::iter;

/// This proof is a non-interactive version of Multiplication-mod-n^s protocol taken from
/// DJ01 [https://www.brics.dk/RS/00/45/BRICS-RS-00-45.pdf ]
/// the prover knows 3 plaintexts a,b,c such that ab = c mod n. The prover goal is to prove that a
/// triplet of ciphertexts encrypts plaintexts a,b,c holding the multiplication relationship
/// Witness: {a,b,c,r_a,r_b,r_c}
/// Statement: {e_a, e_b, e_c, ek}
/// protocol:
/// 1) P picks random values d from Z_n, r_d from Z_n*
///    and computes e_d = Enc_ek(d,r_d), e_db = Enc_ek(db, r_d*r_b)
/// 2) using Fiat-Shamir the parties computes a challenge e
/// 3) P sends f = ea + d mod n , z1 = r_a^e *r_d mod n^2, z2 = r_b^f * (r_db * r_c^e)^-1 mod n^2
/// 4) V checks:
///     e_a^e * e_d = Enc_ek(f, z1),
///     e_b^f*(e_db*e_c^e)^-1 = Enc_pk(0, z2)

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct MulProof {
    pub f: BigInt,
    pub z1: BigInt,
    pub z2: BigInt,
    pub e_d: BigInt,
    pub e_db: BigInt,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct MulWitness {
    pub a: BigInt,
    pub b: BigInt,
    pub c: BigInt,
    pub r_a: BigInt,
    pub r_b: BigInt,
    pub r_c: BigInt,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct MulStatement {
    pub ek: EncryptionKey,
    pub e_a: BigInt,
    pub e_b: BigInt,
    pub e_c: BigInt,
}

impl MulProof {
    pub fn prove(witness: &MulWitness, statement: &MulStatement) -> Result<Self, ()> {
        let d = BigInt::sample_below(&statement.ek.n);
        let r_d = sample_paillier_random(&statement.ek.n);
        let e_d = Paillier::encrypt_with_chosen_randomness(
            &statement.ek,
            RawPlaintext::from(d.clone()),
            &Randomness(r_d.clone()),
        )
        .0
        .into_owned();
        let r_db = &r_d * &witness.r_b;
        let db = &d * &witness.b;
        let e_db = Paillier::encrypt_with_chosen_randomness(
            &statement.ek,
            RawPlaintext::from(db.clone()),
            &Randomness(r_db.clone()),
        )
        .0
        .into_owned();

        let e = super::compute_digest(
            iter::once(&statement.ek.n)
                .chain(iter::once(&statement.e_a))
                .chain(iter::once(&statement.e_b))
                .chain(iter::once(&statement.e_c))
                .chain(iter::once(&e_d))
                .chain(iter::once(&e_db)),
        );

        let ea = BigInt::mod_mul(&e, &witness.a, &statement.ek.n);
        let f = BigInt::mod_add(&ea, &d, &statement.ek.n);
        let r_a_e = BigInt::mod_pow(&witness.r_a, &e, &statement.ek.nn);
        let z1 = BigInt::mod_mul(&r_a_e, &r_d, &statement.ek.nn);
        let r_b_f = BigInt::mod_pow(&witness.r_b, &f, &statement.ek.nn);
        let r_c_e = BigInt::mod_pow(&witness.r_c, &e, &statement.ek.nn);
        let r_db_r_c_e = BigInt::mod_mul(&r_db, &r_c_e, &statement.ek.nn);
        let r_db_r_c_e_inv = r_db_r_c_e.invert(&statement.ek.nn).unwrap();
        let z2 = BigInt::mod_mul(&r_b_f, &r_db_r_c_e_inv, &statement.ek.nn);

        Ok(MulProof {
            f,
            z1,
            z2,
            e_d,
            e_db,
        })
    }

    pub fn verify(&self, statement: &MulStatement) -> Result<(), ()> {
        let e = super::compute_digest(
            iter::once(&statement.ek.n)
                .chain(iter::once(&statement.e_a))
                .chain(iter::once(&statement.e_b))
                .chain(iter::once(&statement.e_c))
                .chain(iter::once(&self.e_d))
                .chain(iter::once(&self.e_db)),
        );

        let enc_f_z1 = Paillier::encrypt_with_chosen_randomness(
            &statement.ek,
            RawPlaintext::from(self.f.clone()),
            &Randomness(self.z1.clone()),
        )
        .0
        .into_owned();
        let enc_0_z2 = Paillier::encrypt_with_chosen_randomness(
            &statement.ek,
            RawPlaintext::from(BigInt::zero()),
            &Randomness(self.z2.clone()),
        )
        .0
        .into_owned();

        let e_a_e = BigInt::mod_pow(&statement.e_a, &e, &statement.ek.nn);
        let e_a_e_e_d = BigInt::mod_mul(&e_a_e, &self.e_d, &statement.ek.nn);
        let e_c_e = BigInt::mod_pow(&statement.e_c, &e, &statement.ek.nn);
        let e_db_e_c_e = BigInt::mod_mul(&self.e_db, &e_c_e, &statement.ek.nn);
        let e_db_e_c_e_inv = e_db_e_c_e.invert(&statement.ek.nn).unwrap();
        let e_b_f = BigInt::mod_pow(&statement.e_b, &self.f, &statement.ek.nn);
        let e_b_f_e_db_e_c_e_inv = BigInt::mod_mul(&e_b_f, &e_db_e_c_e_inv, &statement.ek.nn);

        match e_a_e_e_d == enc_f_z1 && e_b_f_e_db_e_c_e_inv == enc_0_z2 {
            true => Ok(()),
            false => Err(()),
        }
    }
}

fn sample_paillier_random(modulo: &BigInt) -> BigInt {
    let mut r_a = BigInt::sample_below(modulo);
    while BigInt::gcd(&r_a, modulo) != BigInt::one() {
        r_a = BigInt::sample_below(modulo);
    }
    r_a
}

#[cfg(test)]
mod tests {
    use crate::zkproofs::multiplication_proof::sample_paillier_random;
    use crate::zkproofs::multiplication_proof::MulProof;
    use crate::zkproofs::multiplication_proof::MulStatement;
    use crate::zkproofs::multiplication_proof::MulWitness;
    use curv::arithmetic::traits::{Modulo, Samplable};
    use curv::BigInt;
    use paillier::core::Randomness;
    use paillier::traits::EncryptWithChosenRandomness;
    use paillier::traits::KeyGeneration;
    use paillier::Paillier;
    use paillier::RawPlaintext;

    #[test]
    fn test_mul_proof() {
        let (ek, _) = Paillier::keypair().keys();
        let a = BigInt::sample_below(&ek.n);
        let b = BigInt::sample_below(&ek.n);
        let c = BigInt::mod_mul(&a, &b, &ek.n);
        let r_a = sample_paillier_random(&ek.n);
        let r_b = sample_paillier_random(&ek.n);
        let r_c = sample_paillier_random(&ek.n);

        let e_a = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(a.clone()),
            &Randomness(r_a.clone()),
        )
        .0
        .into_owned();

        let e_b = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(b.clone()),
            &Randomness(r_b.clone()),
        )
        .0
        .into_owned();

        let e_c = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(c.clone()),
            &Randomness(r_c.clone()),
        )
        .0
        .into_owned();

        let witness = MulWitness {
            a,
            b,
            c,
            r_a,
            r_b,
            r_c,
        };

        let statement = MulStatement { ek, e_a, e_b, e_c };

        let proof = MulProof::prove(&witness, &statement).unwrap();
        let verify = proof.verify(&statement);
        assert!(verify.is_ok());
    }

    #[test]
    #[should_panic]
    fn test_bad_mul_proof() {
        let (ek, _) = Paillier::keypair().keys();
        let a = BigInt::sample_below(&ek.n);
        let b = BigInt::sample_below(&ek.n);
        let mut c = BigInt::mod_mul(&a, &b, &ek.n);
        // we change c such that c != ab mod m
        c = &c + BigInt::one();
        let r_a = sample_paillier_random(&ek.n);
        let r_b = sample_paillier_random(&ek.n);
        let r_c = sample_paillier_random(&ek.n);

        let e_a = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(a.clone()),
            &Randomness(r_a.clone()),
        )
        .0
        .into_owned();

        let e_b = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(b.clone()),
            &Randomness(r_b.clone()),
        )
        .0
        .into_owned();

        let e_c = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(c.clone()),
            &Randomness(r_c.clone()),
        )
        .0
        .into_owned();

        let witness = MulWitness {
            a,
            b,
            c,
            r_a,
            r_b,
            r_c,
        };

        let statement = MulStatement { ek, e_a, e_b, e_c };

        let proof = MulProof::prove(&witness, &statement).unwrap();
        let verify = proof.verify(&statement);
        assert!(verify.is_ok());
    }
}
