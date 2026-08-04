use super::compression::compress_block;
use super::constants::INITIAL_HASH;
use super::math_utils::words_to_hex;
use super::preprocessing::{preprocess_message, print_preprocessing_steps};
use super::validation::validate_message;

fn run_sha256_demo_internal(message_text: Option<&str>, message_bytes: &[u8]) {
    // Header
    println!("🔐 SHA-256 Hash Algorithm Demo");
    if let Some(text) = message_text {
        println!("Message: \"{}\"", text);
    }
    println!("Message bytes: {:02x?}", message_bytes);
    println!("Message length: {} bytes", message_bytes.len());

    if let Err(e) = validate_message(message_bytes) {
        eprintln!("\n❌ Error: {}", e);
        return;
    }

    // Initial values
    println!("\n=== Initial Hash Values ===");
    println!("  H₀ = 0x6a09e667  (√2)");
    println!("  H₁ = 0xbb67ae85  (√3)");
    println!("  H₂ = 0x3c6ef372  (√5)");
    println!("  H₃ = 0xa54ff53a  (√7)");
    println!("  H₄ = 0x510e527f  (√11)");
    println!("  H₅ = 0x9b05688c  (√13)");
    println!("  H₆ = 0x1f83d9ab  (√17)");
    println!("  H₇ = 0x5be0cd19  (√19)");

    // Preprocess message
    let processed = preprocess_message(message_bytes);
    print_preprocessing_steps(message_bytes, &processed);

    // Process each block
    let mut hash = INITIAL_HASH;

    for (i, block) in processed.blocks.iter().enumerate() {
        println!(
            "\n=== Compression Function (Block {}/{}) ===",
            i + 1,
            processed.blocks.len()
        );
        hash = compress_block(hash, block, true);

        println!("\n  Hash after block {}:", i + 1);
        for (j, word) in hash.iter().enumerate() {
            println!("    H[{}] = 0x{:08x}", j, word);
        }
    }

    // Final hash
    println!("\n=== Final Hash ===");
    println!("  SHA-256: {}", words_to_hex(&hash));

    println!("\n  Hash breakdown:");
    for (i, word) in hash.iter().enumerate() {
        println!("    H[{}] = 0x{:08x}", i, word);
    }

    println!("\n✅ SHA-256 hash computation completed!");
}

// ============================================================================
// Public API - Clean interface for main.rs
// ============================================================================

pub fn run_sha256_demo(message_bytes: Vec<u8>) {
    run_sha256_demo_internal(None, &message_bytes);
}

pub fn run_sha256_demo_text(text: &str) {
    run_sha256_demo_internal(Some(text), text.as_bytes());
}
