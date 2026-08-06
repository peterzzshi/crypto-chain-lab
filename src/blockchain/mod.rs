pub mod chain;
pub mod hash;
pub mod merkle;
pub mod mining;
pub mod types;

pub use chain::{create_genesis, mine_next_block, tamper_block, validate_chain};
pub use types::{Block, Chain, ChainResult, MineBlockResult, MineStep, ValidateResult};
