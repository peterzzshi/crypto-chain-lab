use clap::{Parser, Subcommand};
use encryption_demo::{ecc, rsa, sha256};

#[derive(Parser)]
#[command(name = "encryption-demo")]
#[command(about = "Demonstration of various encryption algorithms")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    algorithm: Algorithm,
}

#[derive(Subcommand)]
enum Algorithm {
    Rsa {
        #[arg(short, long)]
        message: String,

        #[arg(short = 'p')]
        p: String,
        #[arg(short = 'q')]
        q: String,
    },

    Sha256 {
        #[arg(short, long)]
        message: String,
    },

    Ecc {
        /// Hex private key for secp256k1, or decimal scalar (1-12) for demo curve
        #[arg(short, long)]
        key: String,

        /// "secp256k1" (default) or "weierstrass" for E(𝔽₁₁): y²≡x³+x+6 (mod 11)
        #[arg(short, long, default_value = "secp256k1")]
        curve: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.algorithm {
        Algorithm::Rsa { message, p, q } => {
            if message.trim().chars().all(|c| c.is_ascii_digit()) {
                rsa::demo::run_rsa_demo(&message, &p, &q);
            } else {
                rsa::demo::run_rsa_demo_text(&message, &p, &q);
            }
        }
        Algorithm::Sha256 { message } => {
            if message.chars().all(|c| c.is_ascii_hexdigit()) && message.len() % 2 == 0 && !message.is_empty() {
                match hex::decode(&message) {
                    Ok(bytes) => sha256::demo::run_sha256_demo(bytes),
                    Err(_) => sha256::demo::run_sha256_demo_text(&message),
                }
            } else {
                sha256::demo::run_sha256_demo_text(&message);
            }
        }
        Algorithm::Ecc { key, curve } => {
            if let Err(e) = ecc::demo::run_ecc_demo(&key, &curve) {
                eprintln!("\u{274c} Error: {}", e);
            }
        }
    }
}
