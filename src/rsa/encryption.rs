use super::types::{RsaPrivateKey, RsaPublicKey};
use num_bigint::BigUint;

pub fn encrypt(message: &BigUint, public_key: &RsaPublicKey) -> BigUint {
    message.modpow(&public_key.e, &public_key.n)
}

pub fn decrypt(ciphertext: &BigUint, private_key: &RsaPrivateKey) -> BigUint {
    ciphertext.modpow(&private_key.d, &private_key.n)
}
