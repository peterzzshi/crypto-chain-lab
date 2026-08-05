use super::hash::{hash_block_header, meets_difficulty};
use super::mining::mine;
use super::types::{Block, Chain, ChainResult, MineBlockResult, ValidateResult};

pub fn create_genesis(hash_algo: &str, difficulty: u32, timestamp: u64) -> ChainResult {
    let data = "Genesis Block";
    let previous_hash = "0".repeat(64);
    let result = mine(0, timestamp, data, &previous_hash, difficulty, hash_algo);
    let block = Block {
        index: 0,
        timestamp,
        data: data.to_string(),
        previous_hash,
        hash: result.hash,
        nonce: result.nonce,
        difficulty,
        hash_algo: hash_algo.to_string(),
    };
    ChainResult {
        success: true,
        error: None,
        chain: Some(Chain { blocks: vec![block] }),
    }
}

pub fn mine_next_block(
    chain: Chain,
    data: &str,
    hash_algo: &str,
    difficulty: u32,
    timestamp: u64,
) -> MineBlockResult {
    let prev = chain.blocks.last().unwrap();
    let index = prev.index + 1;
    let result = mine(index, timestamp, data, &prev.hash, difficulty, hash_algo);
    let block = Block {
        index,
        timestamp,
        data: data.to_string(),
        previous_hash: prev.hash.clone(),
        hash: result.hash,
        nonce: result.nonce,
        difficulty,
        hash_algo: hash_algo.to_string(),
    };
    let attempts = result.nonce + 1;
    let mut new_chain = chain;
    new_chain.blocks.push(block.clone());
    MineBlockResult {
        success: true,
        error: None,
        block: Some(block),
        chain: Some(new_chain),
        steps: result.steps,
        attempts,
    }
}

pub fn validate_chain(chain: &Chain) -> ValidateResult {
    if chain.blocks.is_empty() {
        return ValidateResult {
            valid: false,
            error: Some("Chain is empty".to_string()),
            invalid_block_index: None,
            message: "Chain is empty".to_string(),
        };
    }
    for (i, block) in chain.blocks.iter().enumerate() {
        let expected = hash_block_header(
            block.index,
            block.timestamp,
            &block.data,
            &block.previous_hash,
            block.nonce,
            &block.hash_algo,
        );
        if expected != block.hash {
            return ValidateResult {
                valid: false,
                error: Some(format!("Block {} has invalid hash", i)),
                invalid_block_index: Some(i as u64),
                message: format!("Block {} hash mismatch — data was tampered!", i),
            };
        }
        if !meets_difficulty(&block.hash, block.difficulty) {
            return ValidateResult {
                valid: false,
                error: Some(format!("Block {} does not meet difficulty {}", i, block.difficulty)),
                invalid_block_index: Some(i as u64),
                message: format!("Block {} proof-of-work invalid", i),
            };
        }
        if i > 0 && block.previous_hash != chain.blocks[i - 1].hash {
            return ValidateResult {
                valid: false,
                error: Some(format!("Block {} previous_hash mismatch", i)),
                invalid_block_index: Some(i as u64),
                message: format!("Block {} is not linked to block {} — chain broken!", i, i - 1),
            };
        }
    }
    ValidateResult {
        valid: true,
        error: None,
        invalid_block_index: None,
        message: format!("Chain valid — {} block(s) verified ✓", chain.blocks.len()),
    }
}

pub fn tamper_block(mut chain: Chain, index: usize, new_data: &str) -> ChainResult {
    if index >= chain.blocks.len() {
        return ChainResult {
            success: false,
            error: Some("Block index out of range".to_string()),
            chain: None,
        };
    }
    chain.blocks[index].data = new_data.to_string();
    ChainResult {
        success: true,
        error: None,
        chain: Some(chain),
    }
}
