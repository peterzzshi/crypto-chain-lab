use encryption_demo::ecc::{
    constants::secp256k1,
    ecdsa::{sign, verify},
    key_generation::keypair_from_hex,
    types::EcdsaSignature,
};
use sha2::{Digest, Sha256};

fn hash(msg: &str) -> [u8; 32] {
    Sha256::digest(msg.as_bytes()).into()
}

const TEST_KEY: &str = "b94f5374fce5edbc8e2a8697c15331677e6ebf0b000000000000000000000001";

#[test]
fn sign_verify_roundtrip() {
    let params = secp256k1();
    let kp = keypair_from_hex(TEST_KEY, &params).unwrap();
    let h = hash("hello world");
    let sig = sign(&h, &kp.private_key, &params).expect("sign must succeed");
    assert!(verify(&h, &sig, &kp.public_key, &params));
}

#[test]
fn wrong_message_fails_verification() {
    let params = secp256k1();
    let kp = keypair_from_hex(TEST_KEY, &params).unwrap();
    let sig = sign(&hash("correct message"), &kp.private_key, &params).unwrap();
    assert!(!verify(&hash("wrong message"), &sig, &kp.public_key, &params));
}

#[test]
fn wrong_public_key_fails_verification() {
    let params = secp256k1();
    let kp1 = keypair_from_hex(TEST_KEY, &params).unwrap();
    let kp2 = keypair_from_hex(
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        &params,
    )
    .unwrap();
    let h = hash("test message");
    let sig = sign(&h, &kp1.private_key, &params).unwrap();
    assert!(!verify(&h, &sig, &kp2.public_key, &params));
}

#[test]
fn deterministic_k_produces_identical_signatures() {
    let params = secp256k1();
    let kp = keypair_from_hex(TEST_KEY, &params).unwrap();
    let h = hash("deterministic");
    let sig1 = sign(&h, &kp.private_key, &params).unwrap();
    let sig2 = sign(&h, &kp.private_key, &params).unwrap();
    assert_eq!(sig1.r, sig2.r);
    assert_eq!(sig1.s, sig2.s);
}

#[test]
fn different_messages_produce_different_signatures() {
    let params = secp256k1();
    let kp = keypair_from_hex(TEST_KEY, &params).unwrap();
    let sig1 = sign(&hash("msg1"), &kp.private_key, &params).unwrap();
    let sig2 = sign(&hash("msg2"), &kp.private_key, &params).unwrap();
    assert_ne!(sig1.r, sig2.r);
}

#[test]
fn mutated_signature_r_fails() {
    use num_bigint::BigUint;
    let params = secp256k1();
    let kp = keypair_from_hex(TEST_KEY, &params).unwrap();
    let h = hash("authentic");
    let sig = sign(&h, &kp.private_key, &params).unwrap();
    let bad_sig = EcdsaSignature { r: sig.r + BigUint::from(1u32), s: sig.s };
    assert!(!verify(&h, &bad_sig, &kp.public_key, &params));
}

#[test]
fn mutated_signature_s_fails() {
    use num_bigint::BigUint;
    let params = secp256k1();
    let kp = keypair_from_hex(TEST_KEY, &params).unwrap();
    let h = hash("authentic");
    let sig = sign(&h, &kp.private_key, &params).unwrap();
    let bad_sig = EcdsaSignature { r: sig.r, s: sig.s + BigUint::from(1u32) };
    assert!(!verify(&h, &bad_sig, &kp.public_key, &params));
}

#[test]
fn cross_check_against_k256_crate() {
    use k256::{
        ecdsa::{SigningKey, VerifyingKey},
    };
    let params = secp256k1();
    let kp = keypair_from_hex(TEST_KEY, &params).unwrap();
    let h = hash("cross-check");
    let our_sig = sign(&h, &kp.private_key, &params).unwrap();

    // Verify our signature using the k256 reference implementation
    let key_bytes = kp.private_key.to_bytes_be();
    let mut padded = [0u8; 32];
    padded[32 - key_bytes.len()..].copy_from_slice(&key_bytes);
    let signing_key = SigningKey::from_bytes(&padded.into()).unwrap();
    let verifying_key = VerifyingKey::from(&signing_key);

    let mut r_bytes = [0u8; 32];
    let mut s_bytes = [0u8; 32];
    let rb = our_sig.r.to_bytes_be();
    let sb = our_sig.s.to_bytes_be();
    r_bytes[32 - rb.len()..].copy_from_slice(&rb);
    s_bytes[32 - sb.len()..].copy_from_slice(&sb);

    let k256_sig = k256::ecdsa::Signature::from_scalars(r_bytes, s_bytes).unwrap();
    // k256 ECDSA verify expects the pre-hashed message bytes
    use k256::ecdsa::signature::DigestVerifier;
    use sha2::Sha256 as K256Sha256;
    let digest = <K256Sha256 as sha2::Digest>::new_with_prefix(b"cross-check");
    assert!(verifying_key.verify_digest(digest, &k256_sig).is_ok());
}
