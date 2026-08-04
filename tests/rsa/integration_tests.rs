use encryption_demo::rsa::encryption::{decrypt, encrypt};
use encryption_demo::rsa::key_generation::generate_keypair;
use encryption_demo::rsa::text_encoding::{number_to_text, text_to_number};
use num_bigint::BigUint;

fn b(n: u64) -> BigUint {
    BigUint::from(n)
}

#[test]
fn numeric_encrypt_decrypt_roundtrip() {
    let keypair = generate_keypair(&b(61), &b(53)).unwrap();
    let message = b(42);
    let ciphertext = encrypt(&message, &keypair.public_key);
    let decrypted = decrypt(&ciphertext, &keypair.private_key);
    assert_eq!(message, decrypted);
}

#[test]
fn text_encrypt_decrypt_roundtrip() {
    let keypair = generate_keypair(&b(251), &b(241)).unwrap();
    let text = "Hi";
    let message = text_to_number(text).unwrap();
    assert!(message < keypair.public_key.n, "message must be smaller than n");
    let ciphertext = encrypt(&message, &keypair.public_key);
    let decrypted = decrypt(&ciphertext, &keypair.private_key);
    let recovered = number_to_text(&decrypted);
    assert_eq!(text, recovered.as_str());
}

#[test]
fn same_message_encrypts_consistently() {
    let keypair = generate_keypair(&b(61), &b(53)).unwrap();
    let message = b(42);
    assert_eq!(
        encrypt(&message, &keypair.public_key),
        encrypt(&message, &keypair.public_key)
    );
}

#[test]
fn different_keypairs_cannot_decrypt_each_other() {
    let kp1 = generate_keypair(&b(61), &b(53)).unwrap();
    let kp2 = generate_keypair(&b(67), &b(71)).unwrap();
    let message = b(42);
    let ciphertext = encrypt(&message, &kp1.public_key);
    assert_ne!(message, decrypt(&ciphertext, &kp2.private_key));
}

#[test]
fn large_primes_encrypt_longer_text() {
    let p = BigUint::from(4294967291u64);
    let q = BigUint::from(4294967279u64);
    let keypair = generate_keypair(&p, &q).unwrap();
    for text in ["Hi", "RSA", "Hello"] {
        let message = text_to_number(text).unwrap();
        assert!(message < keypair.public_key.n);
        let decrypted = decrypt(&encrypt(&message, &keypair.public_key), &keypair.private_key);
        assert_eq!(text, number_to_text(&decrypted).as_str());
    }
}
