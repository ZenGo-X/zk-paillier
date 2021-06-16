/*
    zk-paillier

    Copyright 2018 by Kzen Networks

    zk-paillier is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/zk-paillier/blob/master/LICENSE>
*/

use paillier::{EncryptWithChosenRandomness, EncryptionKey, Paillier, RawPlaintext};

/// Verify correct opening of ciphertext.
pub trait CorrectOpening<R, CT> {
    fn verify_opening(ek: &EncryptionKey, m: RawPlaintext, r: &R, c: &CT) -> bool;
}

impl<R, CT> CorrectOpening<R, CT> for Paillier
where
    Self: for<'a, 'b> EncryptWithChosenRandomness<EncryptionKey, RawPlaintext<'a>, &'b R, CT>,
    CT: PartialEq,
{
    fn verify_opening(ek: &EncryptionKey, m: RawPlaintext, r: &R, c: &CT) -> bool {
        let d = Self::encrypt_with_chosen_randomness(ek, m, r);
        c == &d
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use curv::arithmetic::traits::*;
    use curv::BigInt;
    use paillier::Encrypt;
    use paillier::Keypair;
    use paillier::Open;

    fn test_keypair() -> Keypair {
        let p = BigInt::from_str_radix("148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517", 10).unwrap();
        let q = BigInt::from_str_radix("158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463", 10).unwrap();
        Keypair { p, q }
    }

    #[test]
    fn test_verify() {
        let (ek, dk) = test_keypair().keys();

        let c = Paillier::encrypt(&ek, RawPlaintext::from(BigInt::from(10)));
        let (m, r) = Paillier::open(&dk, &c);

        assert!(Paillier::verify_opening(&ek, m, &r, &c));
    }
}
