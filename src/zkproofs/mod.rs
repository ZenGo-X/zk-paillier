/*
    zk-paillier

    Copyright 2018 by Kzen Networks

    zk-paillier is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/zk-paillier/blob/master/LICENSE>
*/

mod correct_ciphertext;
mod correct_key;
mod correct_key_ni;
mod correct_message;
mod correct_opening;
mod multiplication_proof;
mod range_proof;
mod range_proof_ni;
mod verlin_proof;
mod wi_dlog_proof;
mod zero_enc_proof;

mod errors;
mod utils;

pub use self::{
    correct_ciphertext::*,
    correct_key::{Challenge, CorrectKey, CorrectKeyProof, VerificationAid},
    correct_key_ni::{NiCorrectKeyProof, SALT_STRING},
    correct_message::CorrectMessageProof,
    correct_opening::CorrectOpening,
    multiplication_proof::*,
    range_proof::{ChallengeBits, EncryptedPairs, Proof, RangeProof},
    range_proof_ni::RangeProofNi,
    verlin_proof::*,
    wi_dlog_proof::*,
    zero_enc_proof::*,
};

pub use self::{errors::IncorrectProof, utils::compute_digest};
