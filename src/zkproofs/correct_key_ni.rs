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
// for parameters = e = N, m2 = 11, alpha = 6379 see https://eprint.iacr.org/2018/987.pdf 6.2.3
// for full details.

// product of all primes < alpha: https://www.dcode.fr/primorial
const P: &str = "1824183726245393467247644231302244136093537199057104213213550575243641782740360650490963459819244001947254814805714931325851267161710067435807383848463920901137710041673887113990643820798975386714299839914137592590654009952623014982962684955535111234311335565220917383311689115138496765310625882473439402233109450021984891450304679833752756159872219991089194187575068382762952239830901394850887215392132883640669486674102277756753260855640317510235617660944873631054630816035269100510337643250389997837634640249480037184290462924540150133678312185777228630834940021427688892876384196895677819059963882587092166301131529174343474451480089653483180602591751073139733370712300241581635049350925412683097729232092096276490229965785020041921736307394438075266234968515443716828633392848203945374591926800464450599823553052462708727219173990177119684565306222502415160037753326638045687574106534702341439991863742806351468290587722561435038912863815688133288619512790095919904026573249557024839383595481704184528960978957724597263323512030743875614290609368530643094080051166226135271385866188054556684837921935888945641944961066293159525602885452222458958772845494346799890196718717317906330936509091221354615991671869862034179206244894205681566781062633415772628848878715803040358836098609654889521393046492471227546079924219055408612815173193108753184477562256266860297096223934088509777393752624380757072082427603556077039945700711226680778392737267707541904355129695919972995501581794067880959822149963798096452613619855673307435602850208850402301583025111762622381953251883429317603005626232012725708694401272295509035367654620412640848204179955980722707996291909812529974361949926881288349518750747615837667549305083291804187179123453121466640918862622766511668478452223742058912575427337018022812631386313110243745000214354806312441270889672903307645611658893986526812130032112540367173736664288995222516688120866114984318582900331631896931709005163853429427759224323636152573453333607357348169167915027700846002932742550824939007414330697249569916339964247646402851281857942965519194576006169066153524163225631476643914033601957614124583206541834352791003930506139209204661104882701842617501635864883760885236797081996679496751254260706438583316885612406386543479255566185697792942478704336254208839180970748624881039948192415929866204318800220295457932550799088592217150597176505394120909914475575501881459804699385499576326684695531034075283165800622328491384987194944504461864105986907646706095956083156240472489616473946638879726524585936511018780747174387840018674670110430528051586069422163934697899931456041802624175449157279620104126331489491525955411465073551652840009163781923401029513048693746713122813578721687858104388238796796690";
// salt as system parameter
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

        let salt_bn = BigInt::from(SALT_STRING);

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
        let salt_bn = BigInt::from(SALT_STRING);

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
