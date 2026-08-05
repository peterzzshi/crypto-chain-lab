use encryption_demo::blockchain::hash::{hash_block_header, meets_difficulty};

#[test]
fn sha256_hash_is_64_hex_chars() {
    let h = hash_block_header(0, 1_000_000, "data", &"0".repeat(64), 0, "sha256");
    assert_eq!(h.len(), 64);
    assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn keccak256_hash_is_64_hex_chars() {
    let h = hash_block_header(0, 1_000_000, "data", &"0".repeat(64), 0, "keccak256");
    assert_eq!(h.len(), 64);
    assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn hash_is_deterministic() {
    let a = hash_block_header(1, 999, "hello", "abcd", 42, "sha256");
    let b = hash_block_header(1, 999, "hello", "abcd", 42, "sha256");
    assert_eq!(a, b);
}

#[test]
fn different_nonces_produce_different_hashes() {
    let h0 = hash_block_header(0, 0, "x", "0", 0, "sha256");
    let h1 = hash_block_header(0, 0, "x", "0", 1, "sha256");
    assert_ne!(h0, h1);
}

#[test]
fn meets_difficulty_zero_always_true() {
    assert!(meets_difficulty("abcdef1234567890", 0));
}

#[test]
fn meets_difficulty_checks_leading_zeros() {
    assert!(meets_difficulty("00abcdef", 2));
    assert!(!meets_difficulty("0abcdef0", 2));
    assert!(meets_difficulty("000abc", 3));
    assert!(!meets_difficulty("00abc0", 3));
}
