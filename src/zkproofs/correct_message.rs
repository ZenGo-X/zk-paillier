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
use curv::arithmetic::traits::{Modulo, Samplable};
use curv::BigInt;
use paillier::{EncryptWithChosenRandomness, EncryptionKey, Paillier, Randomness, RawPlaintext};

const B: usize = 256;
/// n the case that the message space size is small (a message can be only one of a few possibilities ),
/// it is possible to create a "ring" like structure that proves that the
/// encrypted value is a message from the message space without revealing the message.
/// reference: https://paillier.daylightingsociety.org/Paillier_Zero_Knowledge_Proof.pdf

#[derive(Debug)]
pub struct CorrectMessageProofError;

pub struct CorrectMessageProof {
    e_vec: Vec<BigInt>,
    z_vec: Vec<BigInt>,
    a_vec: Vec<BigInt>,
    ciphertext: BigInt,
    valid_messages: Vec<BigInt>,
    ek: EncryptionKey,
}

impl CorrectMessageProof {
    pub fn prove(
        ek: &EncryptionKey,
        valid_messages: &[BigInt],
        message_to_encrypt: &BigInt,
    ) -> CorrectMessageProof {
        let num_of_message = valid_messages.len();

        let r = BigInt::sample_below(&ek.n);
        let ciphertext = Paillier::encrypt_with_chosen_randomness(
            ek,
            RawPlaintext::from(message_to_encrypt.clone()),
            &Randomness::from(r.clone()),
        )
        .0
        .into_owned();

        let ui_vec = (0..num_of_message)
            .map(|i| {
                let gm: BigInt = (valid_messages[i].clone() * &ek.n + BigInt::one()) % &ek.nn;
                let gm_inv = gm.invert(&ek.nn).unwrap();
                BigInt::mod_mul(&ciphertext, &gm_inv, &ek.nn)
            })
            .collect::<Vec<BigInt>>();

        let ei_vec = (0..num_of_message - 1)
            .map(|_| BigInt::sample(B))
            .collect::<Vec<BigInt>>();
        let zi_vec = (0..num_of_message - 1)
            .map(|_| BigInt::sample_below(&ek.n))
            .collect::<Vec<BigInt>>();

        let w = BigInt::sample_below(&ek.n);

        let mut j = 0;
        let ai_vec = (0..num_of_message)
            .map(|i| {
                if valid_messages[i] == *message_to_encrypt {
                    BigInt::mod_pow(&w, &ek.n, &ek.nn)
                } else {
                    let zi_n = BigInt::mod_pow(&zi_vec[j], &ek.n, &ek.nn);
                    let ui_ei = BigInt::mod_pow(&ui_vec[i], &ei_vec[j], &ek.nn);
                    let ui_ei_inv = ui_ei.invert(&ek.nn).unwrap();
                    j += 1;
                    BigInt::mod_mul(&zi_n, &ui_ei_inv, &ek.nn)
                }
            })
            .collect::<Vec<BigInt>>();

        let chal = super::compute_digest(ai_vec.iter());
        let two_bn = BigInt::from(2);
        let two_to_security_param: BigInt = two_bn.pow(B as u32);
        let chal = chal.modulus(&two_to_security_param);

        let ei_sum = ei_vec.iter().fold(BigInt::zero(), |acc, x| acc + x);
        let ei_sum = ei_sum.modulus(&two_to_security_param);

        let ei = BigInt::mod_sub(&chal, &ei_sum, &two_to_security_param);
        let ri_ei = BigInt::mod_pow(&r, &ei, &ek.n);
        let zi = BigInt::mod_mul(&w, &ri_ei, &ek.n);

        let mut j = 0;
        let ei_vec_new = (0..num_of_message)
            .map(|i| {
                if valid_messages[i] == *message_to_encrypt {
                    ei.clone()
                } else {
                    let k = j;
                    j += 1;
                    ei_vec[k].clone()
                }
            })
            .collect::<Vec<BigInt>>();

        let mut j = 0;
        let zi_vec_new = (0..num_of_message)
            .map(|i| {
                if valid_messages[i] == *message_to_encrypt {
                    zi.clone()
                } else {
                    let k = j;
                    j += 1;
                    zi_vec[k].clone()
                }
            })
            .collect::<Vec<BigInt>>();
        CorrectMessageProof {
            e_vec: ei_vec_new,
            z_vec: zi_vec_new,
            a_vec: ai_vec,
            ciphertext,
            valid_messages: valid_messages.to_vec(),
            ek: ek.clone(),
        }
    }
    pub fn verify(&self) -> Result<(), CorrectMessageProofError> {
        let num_of_message = self.valid_messages.len();
        let two_bn = BigInt::from(2);
        let two_to_security_param: BigInt = two_bn.pow(B as u32);
        let chal = super::compute_digest(self.a_vec.iter());
        let chal = chal.modulus(&two_to_security_param);
        let ei_sum = self.e_vec.iter().fold(BigInt::zero(), |acc, x| acc + x);
        let ei_sum = ei_sum.modulus(&two_to_security_param);

        assert_eq!(chal, ei_sum);

        let ui_vec = (0..num_of_message)
            .map(|i| {
                let gm: BigInt = (self.valid_messages[i].clone() * self.ek.n.clone()
                    + BigInt::one())
                    % &self.ek.nn;
                let gm_inv = gm.invert(&self.ek.nn).unwrap();
                BigInt::mod_mul(&self.ciphertext, &gm_inv, &self.ek.nn)
            })
            .collect::<Vec<BigInt>>();
        let result_vec = (0..num_of_message)
            .map(|i| {
                let zi_n = BigInt::mod_pow(&self.z_vec[i], &self.ek.n, &self.ek.nn);
                let uk_ek = BigInt::mod_pow(&ui_vec[i], &self.e_vec[i], &self.ek.nn);
                let ak_mul_uk_ek = BigInt::mod_mul(&uk_ek, &self.a_vec[i], &self.ek.nn);
                ak_mul_uk_ek == zi_n
            })
            .collect::<Vec<bool>>();
        if result_vec.iter().all(|&x| x) {
            Ok(())
        } else {
            Err(CorrectMessageProofError)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paillier::KeyGeneration;
    use paillier::Paillier;

    #[test]
    fn test_correct_message_zk_proof() {
        let valid_message = [
            BigInt::from(3),
            BigInt::from(4),
            BigInt::from(5),
            BigInt::from(6),
        ];
        let message_to_encrypt = BigInt::from(4);
        let (ek, _dk) = Paillier::keypair().keys();
        let proof = CorrectMessageProof::prove(&ek, &valid_message, &message_to_encrypt);
        assert!(proof.verify().is_ok());
    }

    #[test]
    #[should_panic]
    fn test_bad_message_zk_proof() {
        let valid_message = [
            BigInt::from(3),
            BigInt::from(4),
            BigInt::from(5),
            BigInt::from(6),
        ];
        let message_to_encrypt = BigInt::from(7);
        let (ek, _dk) = Paillier::keypair().keys();
        let proof = CorrectMessageProof::prove(&ek, &valid_message, &message_to_encrypt);
        assert!(proof.verify().is_ok());
    }
}
