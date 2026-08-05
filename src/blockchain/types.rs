use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct Block {
    pub index: u64,
    pub timestamp: u64,
    pub data: String,
    pub previous_hash: String,
    pub hash: String,
    pub nonce: u64,
    pub difficulty: u32,
    pub hash_algo: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Chain {
    pub blocks: Vec<Block>,
}

#[derive(Serialize, Deserialize)]
pub struct MineStep {
    pub step_number: u32,
    pub title: String,
    pub description: String,
    pub data: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct MineBlockResult {
    pub success: bool,
    pub error: Option<String>,
    pub block: Option<Block>,
    pub chain: Option<Chain>,
    pub steps: Vec<MineStep>,
    pub attempts: u64,
}

#[derive(Serialize, Deserialize)]
pub struct ValidateResult {
    pub valid: bool,
    pub error: Option<String>,
    pub invalid_block_index: Option<u64>,
    pub message: String,
}

#[derive(Serialize, Deserialize)]
pub struct ChainResult {
    pub success: bool,
    pub error: Option<String>,
    pub chain: Option<Chain>,
}
