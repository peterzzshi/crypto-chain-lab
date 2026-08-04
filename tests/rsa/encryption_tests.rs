use encryption_demo::rsa::encryption::{decrypt, encrypt};
use encryption_demo::rsa::types::{RsaPrivateKey, RsaPublicKey};
use num_bigint::BigUint;

fn b(n: u64) -> BigUint {
    BigUint::from(n)
}

#[test]
fn test_encrypt_basic() {
    let public_key = RsaPublicKey { n: b(33), e: b(3) };
    let ciphertext = encrypt(&b(4), &public_key);
    assert_eq!(ciphertext, b(31)); // 4^3 mod 33 = 31
}

#[test]
fn test_decrypt_basic() {
    let private_key = RsaPrivateKey { n: b(33), d: b(7) };
    let decrypted = decrypt(&b(31), &private_key);
    assert_eq!(decrypted, b(4)); // 31^7 mod 33 = 4
}

#[test]
fn test_encrypt_edge_cases() {
    let public_key = RsaPublicKey { n: b(3233), e: b(17) };
    assert_eq!(encrypt(&b(0), &public_key), b(0));
    assert_eq!(encrypt(&b(1), &public_key), b(1));
}
