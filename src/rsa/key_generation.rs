use super::constants::COMMON_PUBLIC_EXPONENTS;
use super::math_utils::mod_inverse;
use super::types::{RsaKeyPair, RsaPrivateKey, RsaPublicKey};
use num_bigint::BigUint;
use num_traits::One;

fn find_exponent_pair(phi_n: &BigUint) -> Option<(BigUint, BigUint)> {
    COMMON_PUBLIC_EXPONENTS.iter().find_map(|&exp| {
        let e = BigUint::from(exp);
        mod_inverse(&e, phi_n).map(|d| (e, d))
    })
}

pub fn generate_keypair(p: &BigUint, q: &BigUint) -> Option<RsaKeyPair> {
    let n = p * q;
    let phi_n = (p - BigUint::one()) * (q - BigUint::one());
    let (e, d) = find_exponent_pair(&phi_n)?;
    Some(RsaKeyPair {
        public_key: RsaPublicKey { n: n.clone(), e },
        private_key: RsaPrivateKey { n, d },
    })
}
