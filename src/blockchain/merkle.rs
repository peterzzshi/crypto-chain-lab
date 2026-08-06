use serde::Serialize;
use crate::sha256::{preprocessing::preprocess_message, compression::compress_block, constants::INITIAL_HASH, math_utils::words_to_hex};

#[derive(Serialize)]
pub struct MerkleResult {
    pub success: bool,
    pub error: Option<String>,
    pub root: Option<String>,
    pub tree: Option<Vec<Vec<String>>>,
    pub leaf_count: usize,
}

fn sha256_hex(data: &str) -> String {
    let bytes = data.as_bytes();
    let processed = preprocess_message(bytes);
    let hash = processed.blocks.iter().fold(INITIAL_HASH, |h, block| compress_block(h, block, false));
    words_to_hex(&hash)
}

pub fn merkle_root(hashes: Vec<String>) -> MerkleResult {
    if hashes.is_empty() {
        return MerkleResult { success: false, error: Some("No blocks in chain".to_string()), root: None, tree: None, leaf_count: 0 };
    }

    let leaf_count = hashes.len();
    let mut tree: Vec<Vec<String>> = vec![hashes];

    while tree.last().map(|l| l.len()).unwrap_or(0) > 1 {
        let level = tree.last().unwrap();
        let next: Vec<String> = level
            .chunks(2)
            .map(|pair| {
                let combined = if pair.len() == 2 {
                    format!("{}{}", pair[0], pair[1])
                } else {
                    format!("{}{}", pair[0], pair[0]) // duplicate odd leaf
                };
                sha256_hex(&combined)
            })
            .collect();
        tree.push(next);
    }

    let root = tree.last().and_then(|l| l.first()).cloned();
    MerkleResult { success: true, error: None, root, tree: Some(tree), leaf_count }
}
