use encryption_demo::blockchain::mining::mine;

#[test]
fn mine_produces_hash_meeting_difficulty_1() {
    let result = mine(0, 1_000_000, "Genesis", &"0".repeat(64), 1, "sha256");
    assert!(result.hash.starts_with('0'), "hash must start with at least one 0");
    assert!(!result.hash.is_empty());
}

#[test]
fn mine_keccak_difficulty_1() {
    let result = mine(0, 1_000_000, "Genesis", &"0".repeat(64), 1, "keccak256");
    assert!(result.hash.starts_with('0'));
}

#[test]
fn mine_nonce_zero_or_higher() {
    let result = mine(0, 1_000_000, "test", &"0".repeat(64), 1, "sha256");
    // nonce must be a valid value (no overflow / sentinel)
    assert!(result.nonce < 2_000_000, "nonce should be within the 2M cap");
}

#[test]
fn mine_steps_structure_within_bounds() {
    let result = mine(0, 1_000_000, "data", &"0".repeat(64), 1, "sha256");
    // 2 header steps + up to 3 failed-attempt steps + 1 success step = max 6
    assert!(result.steps.len() >= 3, "must have at least header + success steps");
    assert!(result.steps.len() <= 6, "at most 2 header + 3 failed + 1 success");
}

#[test]
fn mine_hash_matches_recomputed_header() {
    use encryption_demo::blockchain::hash::hash_block_header;
    let result = mine(5, 9999, "payload", "prevhash", 1, "sha256");
    let recomputed = hash_block_header(5, 9999, "payload", "prevhash", result.nonce, "sha256");
    assert_eq!(result.hash, recomputed);
}
