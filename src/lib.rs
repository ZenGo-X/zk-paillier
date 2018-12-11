#![feature(test)]
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
extern crate bit_vec;
extern crate curv;
extern crate paillier;
extern crate rand;
extern crate rayon;
extern crate ring;
extern crate serde;
extern crate test;

#[macro_use]
extern crate serde_derive;
extern crate serde_json;
mod serialize;
pub mod zkproofs;
