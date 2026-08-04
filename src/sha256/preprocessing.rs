use super::math_utils::bytes_to_words;
use super::types::{Block, ProcessedMessage};

pub fn preprocess_message(message: &[u8]) -> ProcessedMessage {
    let original_length = message.len() as u64;
    let bit_length = original_length * 8;

    let mut padded = message.to_vec();

    // Append single '1' bit (0x80 byte)
    padded.push(0x80);

    // Pad with zeros until length ≡ 448 (mod 512) bits, or 56 (mod 64) bytes
    while (padded.len() % 64) != 56 {
        padded.push(0x00);
    }

    // Append original length as 64-bit big-endian integer
    padded.extend_from_slice(&bit_length.to_be_bytes());

    // Convert to 32-bit words and group into 512-bit blocks
    let words = bytes_to_words(&padded);
    let blocks: Vec<Block> = words
        .chunks(16)
        .map(|chunk| {
            let mut block = [0u32; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            block
        })
        .collect();

    ProcessedMessage {
        blocks,
        original_length,
    }
}

pub fn print_preprocessing_steps(message: &[u8], processed: &ProcessedMessage) {
    println!("\n=== Message Preprocessing ===");
    println!("  Original message: {:?}", String::from_utf8_lossy(message));
    println!("  Original bytes: {:02x?}", message);
    println!(
        "  Original length: {} bytes ({} bits)",
        message.len(),
        message.len() * 8
    );

    // Show padding calculation
    let bit_length = message.len() * 8;
    let after_one_bit = bit_length + 8; // +8 for the '1' bit (0x80 byte)
    let target_length = (after_one_bit + 64).div_ceil(512) * 512;
    let zero_padding_bits = target_length - 64 - after_one_bit; // -64 for length field

    println!("  After adding '1' bit: {} bits", after_one_bit);
    println!(
        "  Zero padding needed: {} bits ({} bytes)",
        zero_padding_bits,
        zero_padding_bits / 8
    );
    println!("  Final length field: 64 bits (8 bytes)");
    println!(
        "  Total padded length: {} bits ({} bytes)",
        target_length,
        target_length / 8
    );
    println!("  Number of 512-bit blocks: {}", processed.blocks.len());

    // Show first block in detail
    if !processed.blocks.is_empty() {
        println!("\n  First block (16 × 32-bit words):");
        for (i, word) in processed.blocks[0].iter().enumerate() {
            println!("    W[{:2}] = 0x{:08x}", i, word);
        }
    }
}
