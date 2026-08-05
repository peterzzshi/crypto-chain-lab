use super::hash::{hash_block_header, meets_difficulty};
use super::types::MineStep;

pub struct MineResult {
    pub hash: String,
    pub nonce: u64,
    pub steps: Vec<MineStep>,
}

pub fn mine(
    index: u64,
    timestamp: u64,
    data: &str,
    previous_hash: &str,
    difficulty: u32,
    hash_algo: &str,
) -> MineResult {
    let mut steps: Vec<MineStep> = Vec::new();
    let target = "0".repeat(difficulty as usize);
    let bits = difficulty * 4;

    steps.push(MineStep {
        step_number: 1,
        title: "Block Header Construction".to_string(),
        description: "Assemble the block header fields. The nonce starts at 0 and increments until the hash meets the difficulty target.".to_string(),
        data: vec![
            format!("Index:         {}", index),
            format!("Timestamp:     {}", timestamp),
            format!("Data:          {}", data),
            format!("Previous Hash: {}", previous_hash),
            format!("Algorithm:     {}", hash_algo),
            format!("Difficulty:    {} (target prefix: \"{}\")", difficulty, target),
        ],
    });

    steps.push(MineStep {
        step_number: 2,
        title: format!("Proof of Work — Difficulty {difficulty}"),
        description: format!(
            "Hash(header ‖ nonce) must begin with {difficulty} zero hex digit(s) — equivalent to {} leading zero bits. Expected average attempts: {}.",
            bits,
            if bits < 64 { (1u64 << bits).to_string() } else { "very large".to_string() }
        ),
        data: vec![
            format!("header = index ‖ timestamp ‖ data ‖ previous_hash ‖ nonce"),
            format!("target prefix: \"{}\"", target),
        ],
    });

    // Show first 3 failed attempts explicitly for educational value
    let mut shown_fails = 0u32;
    let mut nonce: u64 = 0;

    loop {
        let hash = hash_block_header(index, timestamp, data, previous_hash, nonce, hash_algo);

        if meets_difficulty(&hash, difficulty) {
            let step_num = steps.len() as u32 + 1;
            steps.push(MineStep {
                step_number: step_num,
                title: format!("Block Mined — nonce = {nonce}"),
                description: format!(
                    "Valid hash found after {} attempt(s). The hash starts with {} zero(s), satisfying difficulty {}.",
                    nonce + 1, difficulty, difficulty
                ),
                data: vec![
                    format!("Nonce:  {}", nonce),
                    format!("Hash:   {}", hash),
                    format!("header: {}{}{}{}{}", index, timestamp, data, previous_hash, nonce),
                ],
            });
            return MineResult { hash, nonce, steps };
        }

        if shown_fails < 3 {
            let step_num = steps.len() as u32 + 1;
            steps.push(MineStep {
                step_number: step_num,
                title: format!("Attempt nonce = {nonce} — hash mismatch"),
                description: "Hash does not start with the required zero prefix. Increment nonce and try again.".to_string(),
                data: vec![
                    format!("Nonce: {}", nonce),
                    format!("Hash:  {} ✗", hash),
                ],
            });
            shown_fails += 1;
        }

        nonce += 1;
        // Cap at 2M to stay responsive in WASM
        if nonce > 2_000_000 {
            let fallback = hash_block_header(index, timestamp, data, previous_hash, nonce, hash_algo);
            let step_num = steps.len() as u32 + 1;
            steps.push(MineStep {
                step_number: step_num,
                title: "Mining cap reached".to_string(),
                description: "Exceeded 2,000,000 attempts. Lower the difficulty to mine this block.".to_string(),
                data: vec![format!("Nonce reached: {}", nonce)],
            });
            return MineResult { hash: fallback, nonce, steps };
        }
    }
}
