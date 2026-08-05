use encryption_demo::blockchain::chain::{create_genesis, mine_next_block, tamper_block, validate_chain};

fn genesis() -> encryption_demo::blockchain::types::Chain {
    create_genesis("sha256", 1, 1_000_000).chain.unwrap()
}

// ── Genesis ──────────────────────────────────────────────────────────────────

#[test]
fn genesis_block_has_index_zero() {
    let chain = genesis();
    assert_eq!(chain.blocks[0].index, 0);
}

#[test]
fn genesis_hash_meets_difficulty() {
    use encryption_demo::blockchain::hash::meets_difficulty;
    let chain = genesis();
    assert!(meets_difficulty(&chain.blocks[0].hash, 1));
}

#[test]
fn genesis_previous_hash_is_all_zeros() {
    let chain = genesis();
    assert_eq!(chain.blocks[0].previous_hash, "0".repeat(64));
}

// ── Mine next block ───────────────────────────────────────────────────────────

#[test]
fn mine_next_increments_index() {
    let chain = genesis();
    let result = mine_next_block(chain, "Block 1", "sha256", 1, 2_000_000);
    let block = result.block.unwrap();
    assert_eq!(block.index, 1);
}

#[test]
fn mine_next_links_previous_hash() {
    let chain = genesis();
    let genesis_hash = chain.blocks[0].hash.clone();
    let result = mine_next_block(chain, "Block 1", "sha256", 1, 2_000_000);
    let block = result.block.unwrap();
    assert_eq!(block.previous_hash, genesis_hash);
}

#[test]
fn two_block_chain_validates() {
    let chain = genesis();
    let result = mine_next_block(chain, "data", "sha256", 1, 2_000_000);
    let chain2 = result.chain.unwrap();
    assert_eq!(chain2.blocks.len(), 2);
    let v = validate_chain(&chain2);
    assert!(v.valid, "two-block chain must be valid: {}", v.message);
}

#[test]
fn three_block_chain_validates() {
    let chain = genesis();
    let r1 = mine_next_block(chain, "tx:alice->bob:10", "sha256", 1, 2_000_000);
    let r2 = mine_next_block(r1.chain.unwrap(), "tx:bob->carol:5", "sha256", 1, 3_000_000);
    let v = validate_chain(&r2.chain.unwrap());
    assert!(v.valid, "{}", v.message);
}

// ── Validate ─────────────────────────────────────────────────────────────────

#[test]
fn fresh_genesis_is_valid() {
    let chain = genesis();
    let v = validate_chain(&chain);
    assert!(v.valid, "{}", v.message);
}

#[test]
fn empty_chain_is_invalid() {
    use encryption_demo::blockchain::types::Chain;
    let v = validate_chain(&Chain { blocks: vec![] });
    assert!(!v.valid);
}

// ── Tamper ────────────────────────────────────────────────────────────────────

#[test]
fn tamper_invalidates_chain() {
    let chain = genesis();
    let r1 = mine_next_block(chain, "original data", "sha256", 1, 2_000_000);
    let chain2 = r1.chain.unwrap();

    let tampered = tamper_block(chain2, 1, "modified data").chain.unwrap();
    let v = validate_chain(&tampered);
    assert!(!v.valid, "tampered chain must be invalid");
    assert_eq!(v.invalid_block_index, Some(1));
}

#[test]
fn tamper_out_of_range_returns_error() {
    let chain = genesis();
    let result = tamper_block(chain, 99, "bad");
    assert!(!result.success);
    assert!(result.error.is_some());
}

#[test]
fn tamper_genesis_detected() {
    let chain = genesis();
    let tampered = tamper_block(chain, 0, "evil genesis").chain.unwrap();
    let v = validate_chain(&tampered);
    assert!(!v.valid);
    assert_eq!(v.invalid_block_index, Some(0));
}

// ── Keccak-256 variant ────────────────────────────────────────────────────────

#[test]
fn keccak_chain_validates() {
    let chain = create_genesis("keccak256", 1, 1_000_000).chain.unwrap();
    let result = mine_next_block(chain, "keccak block", "keccak256", 1, 2_000_000);
    let v = validate_chain(&result.chain.unwrap());
    assert!(v.valid, "{}", v.message);
}
