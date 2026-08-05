use crate::keccak256::keccak256;
use crate::sha256::{
    compression::compress_block,
    constants::INITIAL_HASH,
    math_utils::words_to_hex,
    preprocessing::preprocess_message,
};

pub fn hash_bytes(data: &[u8], algo: &str) -> String {
    match algo {
        "keccak256" => hex::encode(keccak256(data)),
        _ => {
            let processed = preprocess_message(data);
            let mut state = INITIAL_HASH;
            for block in &processed.blocks {
                state = compress_block(state, block, false);
            }
            words_to_hex(&state)
        }
    }
}

pub fn hash_block_header(
    index: u64,
    timestamp: u64,
    data: &str,
    previous_hash: &str,
    nonce: u64,
    algo: &str,
) -> String {
    let header = format!("{index}{timestamp}{data}{previous_hash}{nonce}");
    hash_bytes(header.as_bytes(), algo)
}

pub fn meets_difficulty(hash: &str, difficulty: u32) -> bool {
    let target = "0".repeat(difficulty as usize);
    hash.starts_with(&target)
}
