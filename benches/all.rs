#[macro_use]
extern crate criterion;
extern crate curv;
extern crate paillier;
extern crate zk_paillier;

use criterion::{Criterion, ParameterizedBenchmark};
use curv::arithmetic::traits::Samplable;
use curv::BigInt;
use paillier::{EncryptWithChosenRandomness, Keypair, Paillier, Randomness, RawPlaintext};
use zk_paillier::zkproofs::RangeProofTrait;
use zk_paillier::zkproofs::{RangeProof, RangeProofNi};

fn range_proof() {
    // TODO: bench range for 256bit range.
    // common:
    let range = BigInt::sample(RANGE_BITS);
    // prover:
    let (ek, _dk) = test_keypair().keys();
    let (verifier_ek, _verifier_dk) = test_keypair().keys();
    // verifier:
    let (_com, _r, e) = RangeProof::verifier_commit(&verifier_ek);
    // prover:
    let (encrypted_pairs, data_and_randmoness_pairs) =
        RangeProof::generate_encrypted_pairs(&ek, &range, STATISTICAL_ERROR_FACTOR);
    // prover:
    let secret_r = BigInt::sample_below(&ek.n);
    let secret_x = BigInt::sample_below(&range.div_floor(&BigInt::from(3)));
    //let secret_x = BigInt::from(0xFFFFFFFi64);
    // common:
    let cipher_x = Paillier::encrypt_with_chosen_randomness(
        &ek,
        RawPlaintext::from(&secret_x),
        &Randomness(secret_r.clone()),
    );
    // verifer decommits (tested in test_commit_decommit)
    // prover:
    let z_vector = RangeProof::generate_proof(
        &ek,
        &secret_x,
        &secret_r,
        &e,
        &range,
        &data_and_randmoness_pairs,
        STATISTICAL_ERROR_FACTOR,
    );
    // verifier:
    let _result = RangeProof::verifier_output(
        &ek,
        &e,
        &encrypted_pairs,
        &z_vector,
        &range,
        &cipher_x.0,
        STATISTICAL_ERROR_FACTOR,
    );
}

fn range_proof_ni() {
    // TODO: bench range for 256bit range.
    let (ek, _dk) = test_keypair().keys();
    let range = BigInt::sample(RANGE_BITS);
    let secret_r = BigInt::sample_below(&ek.n);
    let secret_x = BigInt::sample_below(&range.div_floor(&BigInt::from(3)));
    let cipher_x = Paillier::encrypt_with_chosen_randomness(
        &ek,
        RawPlaintext::from(&secret_x),
        &Randomness(secret_r.clone()),
    );
    let range_proof = RangeProofNi::prove(&ek, &range, &cipher_x.0, &secret_x, &secret_r);

    range_proof
        .verify(&ek, &cipher_x.0)
        .expect("range proof error");
}

fn test_keypair() -> Keypair {
    let p = str::parse("148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517").unwrap();
    let q = str::parse("158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463").unwrap();
    Keypair { p, q }
}

const RANGE_BITS: usize = 256; //for elliptic curves with 256bits for example

fn criterion_benchmark(c: &mut Criterion) {
    c.bench(
        "range proof",
        ParameterizedBenchmark::new("few", |b, _| b.iter(|| range_proof()), vec![0])
            .sample_size(20),
    );
    c.bench(
        "range proof ni",
        ParameterizedBenchmark::new("few", |b, _| b.iter(|| range_proof_ni()), vec![0])
            .sample_size(10),
    );
}

const STATISTICAL_ERROR_FACTOR: usize = 40;

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
