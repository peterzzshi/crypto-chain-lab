use encryption_demo::keccak256::keccak256;

#[test]
fn keccak256_empty_string_known_vector() {
    // keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    let hash = keccak256(b"");
    assert_eq!(
        hex::encode(hash),
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    );
}

#[test]
fn keccak256_abc_known_vector() {
    // keccak256("abc") = 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
    let hash = keccak256(b"abc");
    assert_eq!(
        hex::encode(hash),
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    );
}

#[test]
fn keccak256_hello_world_known_vector() {
    // keccak256("Hello, World!") — reference from eth_utils keccak256
    let hash = keccak256(b"Hello, World!");
    assert_eq!(
        hex::encode(hash),
        "acaf3289d7b601cbd114fb36c4d29c85bbfd5e133f14cb355c3fd8d99367964f"
    );
}

#[test]
fn keccak256_not_sha3_256() {
    // SHA3-256("abc") ≠ Keccak-256("abc") — they differ only in padding byte
    let keccak = keccak256(b"abc");
    // SHA3-256("abc") = 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
    let sha3_hex = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532";
    assert_ne!(hex::encode(keccak), sha3_hex, "Keccak-256 and SHA3-256 must produce different digests");
}
