use encryption_demo::aes128::cipher::{decrypt_block, encrypt_block};
use encryption_demo::aes128::demo::run_aes128_demo;

fn hex_to_bytes16(s: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

// FIPS 197 Appendix B worked example.
#[test]
fn aes128_fips197_appendix_b_vector() {
    let plaintext = hex_to_bytes16("3243f6a8885a308d313198a2e0370734");
    let key = hex_to_bytes16("2b7e151628aed2a6abf7158809cf4f3c");
    let expected_ciphertext = hex_to_bytes16("3925841d02dc09fbdc118597196a0b32");

    let ciphertext = encrypt_block(&plaintext, &key);
    assert_eq!(ciphertext, expected_ciphertext);

    let decrypted = decrypt_block(&ciphertext, &key);
    assert_eq!(decrypted, plaintext);
}

// FIPS 197 Appendix C.1 known-answer test (AES-128).
#[test]
fn aes128_fips197_appendix_c1_vector() {
    let plaintext = hex_to_bytes16("00112233445566778899aabbccddeeff");
    let key = hex_to_bytes16("000102030405060708090a0b0c0d0e0f");
    let expected_ciphertext = hex_to_bytes16("69c4e0d86a7b0430d8cdb78070b4c55a");

    let ciphertext = encrypt_block(&plaintext, &key);
    assert_eq!(ciphertext, expected_ciphertext);

    let decrypted = decrypt_block(&ciphertext, &key);
    assert_eq!(decrypted, plaintext);
}

#[test]
fn aes128_round_trip_is_identity_for_arbitrary_input() {
    let plaintext = hex_to_bytes16("deadbeefcafebabe0123456789abcdef");
    let key = hex_to_bytes16("ffeeddccbbaa99887766554433221100");

    let ciphertext = encrypt_block(&plaintext, &key);
    assert_ne!(ciphertext, plaintext, "ciphertext should differ from plaintext");

    let decrypted = decrypt_block(&ciphertext, &key);
    assert_eq!(decrypted, plaintext);
}

#[test]
fn aes128_all_zero_block_and_key() {
    let plaintext = [0u8; 16];
    let key = [0u8; 16];
    let expected_ciphertext = hex_to_bytes16("66e94bd4ef8a2c3b884cfa59ca342b2e");

    let ciphertext = encrypt_block(&plaintext, &key);
    assert_eq!(ciphertext, expected_ciphertext);
    assert_eq!(decrypt_block(&ciphertext, &key), plaintext);
}

#[test]
fn aes128_demo_reports_success_and_matches_cipher_primitives() {
    let plaintext = hex_to_bytes16("00112233445566778899aabbccddeeff");
    let key = hex_to_bytes16("000102030405060708090a0b0c0d0e0f");

    let result = run_aes128_demo(&plaintext, &key);

    assert!(result.success, "demo should verify decrypt(encrypt(p)) == p");
    assert_eq!(result.ciphertext_hex, "69c4e0d86a7b0430d8cdb78070b4c55a");
    assert_eq!(result.decrypted_hex, result.plaintext_hex);
    // Key schedule + initial AddRoundKey + 10 rounds + verification = 13 steps.
    assert_eq!(result.steps.len(), 13);
}

#[test]
fn aes128_demo_step_titles_cover_all_rounds() {
    let plaintext = [0u8; 16];
    let key = [0u8; 16];

    let result = run_aes128_demo(&plaintext, &key);
    assert_eq!(result.steps[0].title, "Key Schedule");
    assert_eq!(result.steps[1].title, "Initial AddRoundKey (Round 0)");
    assert!(result.steps[10].title.starts_with("Round 9"));
    assert!(result.steps[11].title.starts_with("Round 10"));
    assert_eq!(result.steps[12].title, "Decryption Verification");
}
