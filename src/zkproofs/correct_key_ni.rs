/*
    zk-paillier

    Copyright 2018 by Kzen Networks

    zk-paillier is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/zk-paillier/blob/master/LICENSE>
*/
use std::iter;
use std::ops::Shl;

use curv::arithmetic::traits::*;
use curv::BigInt;
use paillier::{extract_nroot, DecryptionKey, EncryptionKey};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
// This protocol is based on the NIZK protocol in https://eprint.iacr.org/2018/057.pdf
// for parameters = e = N, m2 = 11, alpha = 6370 see https://eprint.iacr.org/2018/987.pdf 6.2.3
// for full details.

// product of all primes < alpha
const P: &str = "44871651744009136248115543081640547413785854417842050160655833875792914833852769205831424979368719986889519256934239452438251108738670217298542180982547421007901019408155961940142468907900676141149633188172029947498666222471142795699128314649438784106402197023949268047384343715946006767671319388463922366703585708460135453240679421061304864609915827908896062350138633849514905858373339528086006145373712431756746905467935232935398951226852071323775412278763371089401544920873813490290672436809231516731065356763193493525160238868779310055137922174496115680527519932793977258424479253973670103634070028863591207614649216492780891961054287421831028229266989697058385612003557825398202548657910983931484180193293615175594925895929359108723671212631368891689462486968022029482413912928883488902454913524492340322599922718890878760895105937402913873414377276608236656947832307175090505396675623505955607363683869194683635689701238311577953994900734498406703176954324494694474545570839360607926610248093452739817614097197031607820417729009847465138388398887861935127785385309564525648905444610640901769290645369888935446477559073843982605496992468605588284307311971153579731703863970674466666844817336319390617551354845025116350295041840093627836067370100384861820888752358520276041000456608056339377573485917445104757987800101659688183150320442308091835974182809184299472568260682774683272697993855730500061223160274918361373258473553412704497335663924406111413972911417644029226449602417135116011968946232623154008710271296183350215563946003547561056456285939676838623311370087238225630994506113422922846572616538637723054222166159389475617214681282874373185283568512603887750846072033376432252677883915884203823739988948315257311383912016966925295975180180438969999175030785077627458887411146486902613291202008193902979800279637509789564807502239686755727063367075758492823731724669702442450502667810890608807091448688985203084972035197770874223259420649055450382725355162738490355628688943706634905982449810389530661328557381850782677221561924983234877936783136471890539395124220965982831778882400224156689487137227198030461624542872774217771594215907203725682315714199249588874271661233929713660269883273404764648327455796699366900022345171030564747210542398285078804310752063852249740561571105640741618793118627170070315410588646442647771802031066589341358879304845579387079972404386434238273904239604603511925708377008467129590636257287965232576327580009018475271364237665836186806027331208426256451429549641988386585949300254487647395222785274120561299318070944530096970076560461229486504018773252771360855091191876004370694539453020462096690084476681253865429278552786361828508910022714749051734108364178374765700925133405508684883070";
// salt string "kzen" as system parameter, which is hashed to 256 bit
const SALT_STRING: &[u8] = &[75, 90, 101, 110];
const M2: usize = 11;
const DIGEST_SIZE: usize = 256;
#[derive(Debug)]
pub struct CorrectKeyProofError;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NICorrectKeyProof {
    #[serde(with = "crate::serialize::vecbigint")]
    pub sigma_vec: Vec<BigInt>,
}

impl NICorrectKeyProof {
    pub fn proof(dk: &DecryptionKey) -> NICorrectKeyProof {
        let dk_n = &dk.q * &dk.p;
        let key_length = dk_n.bit_length();

        let salt_bn = super::compute_digest(iter::once(BigInt::from(SALT_STRING)));

        // TODO: use flatten (Morten?)
        let rho_vec = (0..M2)
            .map(|i| {
                let seed_bn = super::compute_digest(
                    iter::once(&dk_n)
                        .chain(iter::once(&salt_bn))
                        .chain(iter::once(&BigInt::from(i as u32))),
                );
                //   let seed_bn = BigInt::from(&seed[..]);
                mask_generation(key_length, &seed_bn) % &dk_n
            })
            .collect::<Vec<BigInt>>();

        let sigma_vec = rho_vec
            .iter()
            .map(|i| extract_nroot(dk, i))
            .collect::<Vec<BigInt>>();
        NICorrectKeyProof { sigma_vec }
    }

    pub fn verify(&self, ek: &EncryptionKey) -> Result<(), CorrectKeyProofError> {
        let key_length = ek.n.bit_length() as usize;
        let salt_bn = super::compute_digest(iter::once(BigInt::from(SALT_STRING)));

        let rho_vec = (0..M2)
            .map(|i| {
                let seed_bn = super::compute_digest(
                    iter::once(&ek.n)
                        .chain(iter::once(&salt_bn))
                        .chain(iter::once(&BigInt::from(i as u32))),
                );
                mask_generation(key_length, &seed_bn) % &ek.n
            })
            .collect::<Vec<BigInt>>();
        let alpha_primorial: BigInt = str::parse(&P).unwrap();
        let gcd_test = alpha_primorial.gcd(&ek.n);

        let derived_rho_vec = (0..M2)
            .into_par_iter()
            .map(|i| BigInt::mod_pow(&self.sigma_vec[i], &ek.n, &ek.n))
            .collect::<Vec<BigInt>>();

        if rho_vec == derived_rho_vec && gcd_test == BigInt::one() {
            Ok(())
        } else {
            Err(CorrectKeyProofError)
        }
    }
}

// generate random element of size :
// based on https://tools.ietf.org/html/rfc8017#appendix-B.2.1
pub fn mask_generation(out_length: usize, seed: &BigInt) -> BigInt {
    let msklen = out_length / DIGEST_SIZE + 1; // adding one sha256 is more efficient then rejection sampling (see A.4 (e) in the paper)
    let msklen_hash_vec = (0..msklen)
        .map(|j| {
            super::compute_digest(iter::once(seed).chain(iter::once(&BigInt::from(j as u32))))
            // concat elements of  msklen_hash_vec to one long element
        })
        .collect::<Vec<BigInt>>();
    msklen_hash_vec
        .iter()
        .zip(0..msklen)
        .fold(BigInt::zero(), |acc, x| acc + x.0.shl(x.1 * DIGEST_SIZE))
}

#[cfg(test)]
mod tests {
    use super::*;
    use paillier::KeyGeneration;
    use paillier::Paillier;

    #[test]
    fn test_correct_zk_proof() {
        let (ek, dk) = Paillier::keypair().keys();
        let proof = NICorrectKeyProof::proof(&dk);
        assert!(proof.verify(&ek).is_ok());
    }
}
