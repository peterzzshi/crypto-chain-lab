use num_bigint::BigUint;

pub fn text_to_number(text: &str) -> Option<BigUint> {
    if text.is_empty() {
        return None;
    }
    Some(BigUint::from_bytes_be(text.as_bytes()))
}

pub fn number_to_text(n: &BigUint) -> String {
    String::from_utf8_lossy(&n.to_bytes_be()).to_string()
}

// block_size = floor((n.bits() - 1) / 8) bytes per block; requires n > 255 (p, q > 16).
pub fn text_to_blocks(text: &str, n: &BigUint) -> Vec<BigUint> {
    let block_size = ((n.bits() - 1) / 8) as usize;
    if block_size == 0 {
        return vec![];
    }
    text.as_bytes()
        .chunks(block_size)
        .map(BigUint::from_bytes_be)
        .collect()
}

pub fn blocks_to_text(blocks: &[BigUint]) -> String {
    let bytes: Vec<u8> = blocks.iter().flat_map(|b| b.to_bytes_be()).collect();
    String::from_utf8_lossy(&bytes).to_string()
}
