pub type Word = u32;
pub type Block = [Word; 16];
pub type Hash = [Word; 8];

#[derive(Debug, Clone)]
pub struct Sha256State {
    pub hash: Hash,
    pub message_length: u64,
}

#[derive(Debug, Clone)]
pub struct ProcessedMessage {
    pub blocks: Vec<Block>,
    pub original_length: u64,
}
