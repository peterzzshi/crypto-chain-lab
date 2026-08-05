use encryption_demo::sha256::compression::compress_block;
use encryption_demo::sha256::constants::INITIAL_HASH;
use encryption_demo::sha256::math_utils::words_to_hex;
use encryption_demo::sha256::preprocessing::preprocess_message;

fn sha256_native(input: &[u8]) -> String {
    let processed = preprocess_message(input);
    let mut hash = INITIAL_HASH;
    for block in &processed.blocks {
        hash = compress_block(hash, block, false);
    }
    words_to_hex(&hash)
}

fn sha256_reference(input: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input);
    format!("{:x}", hasher.finalize())
}

#[test]
fn sha256_empty_string_matches_reference() {
    assert_eq!(sha256_native(b""), sha256_reference(b""));
}

#[test]
fn sha256_abc_matches_reference() {
    assert_eq!(sha256_native(b"abc"), sha256_reference(b"abc"));
}

#[test]
fn sha256_hello_world_matches_reference() {
    assert_eq!(sha256_native(b"Hello, World!"), sha256_reference(b"Hello, World!"));
}

#[test]
fn sha256_nist_vector_448bit_boundary() {
    // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" — FIPS 180-4 example
    let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    assert_eq!(sha256_native(input), sha256_reference(input));
}

#[test]
fn sha256_known_digest_for_empty() {
    assert_eq!(
        sha256_native(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn sha256_known_digest_for_abc() {
    assert_eq!(
        sha256_native(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}
