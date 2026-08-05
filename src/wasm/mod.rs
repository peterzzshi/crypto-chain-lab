use num_bigint::BigUint;
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::ecc::constants::secp256k1;
use crate::ecc::key_generation::keypair_from_hex;
use crate::ecc::math_utils::{point_to_str, scalar_mul_with_steps};
use crate::ecc::types::CurvePoint;
use crate::rsa::encryption::{decrypt, encrypt};
use crate::rsa::key_generation::generate_keypair;
use crate::rsa::math_utils::is_prime;
use crate::rsa::text_encoding::number_to_text;
use crate::blockchain::{
    chain::{create_genesis, mine_next_block, tamper_block, validate_chain},
    types::{Chain, ChainResult, MineBlockResult},
};
use crate::ecc::ecdsa::{sign as ecdsa_sign_inner, verify as ecdsa_verify_inner};
use crate::ecc::types::{EcdsaSignResult, EcdsaVerifyResult};
use crate::keccak256::keccak256_with_steps;
use crate::sha256::compression::compress_block;
use crate::sha256::constants::INITIAL_HASH;
use crate::sha256::math_utils::words_to_hex;
use crate::sha256::preprocessing::preprocess_message;

fn to_json<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string())
}

// ============================================================================
// RSA Types
// ============================================================================

#[derive(Serialize, Deserialize)]
pub struct RsaKeyPairResult {
    pub n: String,
    pub e: String,
    pub d: String,
    pub p: String,
    pub q: String,
    pub phi_n: String,
}

#[derive(Serialize, Deserialize)]
pub struct RsaBlock {
    pub index: usize,
    pub text_chunk: String,
    pub message_number: String,
    pub ciphertext: String,
    pub decrypted_number: String,
}

#[derive(Serialize, Deserialize)]
pub struct RsaStep {
    pub step_number: u32,
    pub title: String,
    pub description: String,
    pub formula: String,
    pub result: String,
}

#[derive(Serialize, Deserialize)]
pub struct RsaDemoResult {
    pub success: bool,
    pub error: Option<String>,
    pub original_message: String,
    pub message_number: String,
    pub key_pair: Option<RsaKeyPairResult>,
    pub ciphertext: String,
    pub decrypted_number: String,
    pub decrypted_text: Option<String>,
    pub steps: Vec<RsaStep>,
    pub blocks: Vec<RsaBlock>,
}

fn rsa_error(msg: String, orig: String, message_number: String) -> RsaDemoResult {
    RsaDemoResult {
        success: false,
        error: Some(msg),
        original_message: orig,
        message_number,
        key_pair: None,
        ciphertext: "0".to_string(),
        decrypted_number: "0".to_string(),
        decrypted_text: None,
        steps: vec![],
        blocks: vec![],
    }
}

// ============================================================================
// SHA-256 Types
// ============================================================================

#[derive(Serialize, Deserialize)]
pub struct Sha256Step {
    pub step_number: u32,
    pub title: String,
    pub description: String,
    pub data: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Sha256DemoResult {
    pub success: bool,
    pub error: Option<String>,
    pub original_message: String,
    pub message_bytes: Vec<u8>,
    pub hash: String,
    pub hash_words: Vec<String>,
    pub steps: Vec<Sha256Step>,
}

// ============================================================================
// ECC Types
// ============================================================================

#[derive(Serialize, Deserialize)]
pub struct EccStep {
    pub step_number: u32,
    pub title: String,
    pub description: String,
    pub formula: String,
    pub result: String,
}

#[derive(Serialize, Deserialize)]
pub struct EccKeyPairResult {
    pub private_key: String,
    pub public_key_x: String,
    pub public_key_y: String,
    pub public_key_compressed: Option<String>,
    pub public_key_uncompressed: Option<String>,
    pub curve: String,
}

#[derive(Serialize, Deserialize)]
pub struct EccDemoResult {
    pub success: bool,
    pub error: Option<String>,
    pub key_pair: Option<EccKeyPairResult>,
    pub steps: Vec<EccStep>,
}

fn ecc_error(msg: String) -> EccDemoResult {
    EccDemoResult {
        success: false,
        error: Some(msg),
        key_pair: None,
        steps: vec![],
    }
}

// ============================================================================
// RSA WASM Functions
// ============================================================================

fn parse_prime(s: &str) -> Result<BigUint, String> {
    let s = s.trim();
    let (digits, radix) = if s.starts_with("0x") || s.starts_with("0X") {
        (&s[2..], 16u32)
    } else {
        (s, 10u32)
    };
    BigUint::parse_bytes(digits.as_bytes(), radix).ok_or_else(|| format!("'{}' is not a valid number", s))
}

fn parse_number_str(s: &str) -> BigUint {
    let s = s.trim();
    let (digits, radix) = if s.starts_with("0x") || s.starts_with("0X") {
        (&s[2..], 16u32)
    } else {
        (s, 10u32)
    };
    BigUint::parse_bytes(digits.as_bytes(), radix).unwrap_or_default()
}

fn fmt_bigint(n: &BigUint) -> String {
    if n.bits() <= 64 {
        n.to_str_radix(10)
    } else {
        format!("0x{}", n.to_str_radix(16))
    }
}

#[wasm_bindgen]
pub fn rsa_demo_number(message: &str, p: &str, q: &str) -> String {
    let p = match parse_prime(p) {
        Ok(v) => v,
        Err(e) => return to_json(&rsa_error(e, message.to_string(), "0".to_string())),
    };
    let q = match parse_prime(q) {
        Ok(v) => v,
        Err(e) => return to_json(&rsa_error(e, message.to_string(), "0".to_string())),
    };
    to_json(&run_rsa_demo_internal(None, parse_number_str(message), p, q))
}

#[wasm_bindgen]
pub fn rsa_demo_text(text: &str, p: &str, q: &str) -> String {
    let p = match parse_prime(p) {
        Ok(v) => v,
        Err(e) => return to_json(&rsa_error(e, text.to_string(), "0".to_string())),
    };
    let q = match parse_prime(q) {
        Ok(v) => v,
        Err(e) => return to_json(&rsa_error(e, text.to_string(), "0".to_string())),
    };
    if text.is_empty() {
        return to_json(&rsa_error("text is empty".to_string(), text.to_string(), "0".to_string()));
    }
    to_json(&run_rsa_demo_internal(Some(text.to_string()), BigUint::default(), p, q))
}

#[wasm_bindgen]
pub fn validate_prime(n: &str) -> bool {
    parse_prime(n).map(|v| is_prime(&v)).unwrap_or(false)
}

fn run_rsa_demo_internal(
    message_text: Option<String>,
    message_number: BigUint,
    p: BigUint,
    q: BigUint,
) -> RsaDemoResult {
    let mut steps = Vec::new();
    let orig = message_text.clone().unwrap_or_else(|| fmt_bigint(&message_number));

    if !is_prime(&p) {
        return rsa_error(format!("{} is not a prime number", p), orig, "0".to_string());
    }
    if !is_prime(&q) {
        return rsa_error(format!("{} is not a prime number", q), orig, "0".to_string());
    }
    if p == q {
        return rsa_error(
            "p and q must be different prime numbers".to_string(),
            orig,
            "0".to_string(),
        );
    }

    let n = &p * &q;
    steps.push(RsaStep {
        step_number: 1,
        title: "Calculate n (modulus)".to_string(),
        description: "Multiply the two prime numbers to get n".to_string(),
        formula: format!("n = p \u{00d7} q = {} \u{00d7} {}", p, q),
        result: fmt_bigint(&n),
    });

    let phi_n = (p.clone() - BigUint::one()) * (q.clone() - BigUint::one());
    steps.push(RsaStep {
        step_number: 2,
        title: "Calculate \u{03c6}(n) (Euler's totient)".to_string(),
        description: "\u{03c6}(n) = (p-1)(q-1) counts integers coprime to n".to_string(),
        formula: format!("\u{03c6}(n) = ({}-1) \u{00d7} ({}-1)", p, q),
        result: fmt_bigint(&phi_n),
    });

    let key_pair = match generate_keypair(&p, &q) {
        Some(kp) => kp,
        None => {
            return rsa_error(
                "Could not find a valid public exponent. Try different primes.".to_string(),
                orig,
                "0".to_string(),
            );
        }
    };

    steps.push(RsaStep {
        step_number: 3,
        title: "Select public exponent e".to_string(),
        description: "Choose e such that gcd(e, \u{03c6}(n)) = 1".to_string(),
        formula: format!("e = {} (coprime with \u{03c6}(n))", fmt_bigint(&key_pair.public_key.e)),
        result: fmt_bigint(&key_pair.public_key.e),
    });

    steps.push(RsaStep {
        step_number: 4,
        title: "Calculate private exponent d".to_string(),
        description: "Find d such that e \u{00d7} d \u{2261} 1 (mod \u{03c6}(n))".to_string(),
        formula: "d = e\u{207b}\u{00b9} mod \u{03c6}(n)".to_string(),
        result: fmt_bigint(&key_pair.private_key.d),
    });

    let check = (key_pair.public_key.e.clone() * key_pair.private_key.d.clone()) % &phi_n;
    steps.push(RsaStep {
        step_number: 5,
        title: "Verify key pair".to_string(),
        description: "Confirm that e \u{00d7} d \u{2261} 1 (mod \u{03c6}(n))".to_string(),
        formula: format!(
            "{} \u{00d7} {} mod {}",
            fmt_bigint(&key_pair.public_key.e),
            fmt_bigint(&key_pair.private_key.d),
            fmt_bigint(&phi_n)
        ),
        result: if check == BigUint::one() {
            "\u{2713} Valid".to_string()
        } else {
            "\u{2717} Invalid".to_string()
        },
    });

    // TEXT MODE: block encoding — each chunk of floor((n.bits()-1)/8) bytes is a separate RSA operation
    if let Some(ref text) = message_text {
        let block_size = ((n.bits() - 1) / 8) as usize;
        if block_size == 0 {
            return rsa_error(
                "n is too small for block encoding (need n > 255; choose p, q > 16)".to_string(),
                orig,
                "0".to_string(),
            );
        }
        steps.push(RsaStep {
            step_number: 6,
            title: "Block Encoding".to_string(),
            description: format!(
                "block_size = \u{230a}(n.bits()\u{2212}1)/8\u{230b} = \u{230a}({}\u{2212}1)/8\u{230b} = {} byte(s)/block. Each block m\u{1d62} < n satisfies RSA\u{2019}s m < n constraint.",
                n.bits(), block_size
            ),
            formula: format!("\"{}\" \u{2192} {} block(s)", text, (text.len() + block_size - 1) / block_size),
            result: format!("{} byte(s)/block", block_size),
        });

        let mut blocks: Vec<RsaBlock> = Vec::new();
        let mut all_ok = true;
        for (i, chunk) in text.as_bytes().chunks(block_size).enumerate() {
            let m = BigUint::from_bytes_be(chunk);
            let c = encrypt(&m, &key_pair.public_key);
            let d = decrypt(&c, &key_pair.private_key);
            if m != d {
                all_ok = false;
            }
            blocks.push(RsaBlock {
                index: i,
                text_chunk: String::from_utf8_lossy(chunk).to_string(),
                message_number: fmt_bigint(&m),
                ciphertext: fmt_bigint(&c),
                decrypted_number: fmt_bigint(&d),
            });
        }

        let decrypted_bytes: Vec<u8> = blocks
            .iter()
            .flat_map(|b| {
                BigUint::parse_bytes(b.decrypted_number.as_bytes(), 10)
                    .unwrap_or_default()
                    .to_bytes_be()
            })
            .collect();
        let decrypted_text = String::from_utf8_lossy(&decrypted_bytes).to_string();

        steps.push(RsaStep {
            step_number: 7,
            title: "Verification".to_string(),
            description: "Each block decrypts back to its original bytes".to_string(),
            formula: format!("decrypt(encrypt(m\u{1d62})) == m\u{1d62} for all {} block(s)", blocks.len()),
            result: if all_ok { "\u{2713} Success!".to_string() } else { "\u{2717} Failed!".to_string() },
        });

        return RsaDemoResult {
            success: all_ok,
            error: None,
            original_message: orig,
            message_number: "0".to_string(),
            key_pair: Some(RsaKeyPairResult {
                n: fmt_bigint(&n),
                e: fmt_bigint(&key_pair.public_key.e),
                d: fmt_bigint(&key_pair.private_key.d),
                p: fmt_bigint(&p),
                q: fmt_bigint(&q),
                phi_n: fmt_bigint(&phi_n),
            }),
            ciphertext: "0".to_string(),
            decrypted_number: "0".to_string(),
            decrypted_text: Some(decrypted_text),
            steps,
            blocks,
        };
    }

    // NUMBER MODE: single-integer RSA
    if message_number >= n {
        return RsaDemoResult {
            success: false,
            error: Some(format!("Message integer ({}) \u{2265} n ({}). RSA requires m < n \u{2014} use larger primes or a shorter message.", fmt_bigint(&message_number), fmt_bigint(&n))),
            original_message: orig,
            message_number: fmt_bigint(&message_number),
            key_pair: Some(RsaKeyPairResult {
                n: fmt_bigint(&n),
                e: fmt_bigint(&key_pair.public_key.e),
                d: fmt_bigint(&key_pair.private_key.d),
                p: fmt_bigint(&p),
                q: fmt_bigint(&q),
                phi_n: fmt_bigint(&phi_n),
            }),
            ciphertext: "0".to_string(),
            decrypted_number: "0".to_string(),
            decrypted_text: None,
            steps,
            blocks: vec![],
        };
    }

    let ciphertext = encrypt(&message_number, &key_pair.public_key);
    steps.push(RsaStep {
        step_number: 6,
        title: "Encryption".to_string(),
        description: "Calculate ciphertext using public key".to_string(),
        formula: "c = m^e mod n".to_string(),
        result: fmt_bigint(&ciphertext),
    });

    let decrypted_number = decrypt(&ciphertext, &key_pair.private_key);
    steps.push(RsaStep {
        step_number: 7,
        title: "Decryption".to_string(),
        description: "Recover original message using private key".to_string(),
        formula: "m = c^d mod n".to_string(),
        result: fmt_bigint(&decrypted_number),
    });

    let decrypted_text = message_text.as_ref().map(|_| number_to_text(&decrypted_number));
    let success = message_number == decrypted_number;

    steps.push(RsaStep {
        step_number: 8,
        title: "Verification".to_string(),
        description: "Compare original and decrypted messages".to_string(),
        formula: format!(
            "original {} == decrypted {}",
            fmt_bigint(&message_number),
            fmt_bigint(&decrypted_number)
        ),
        result: if success {
            "\u{2713} Success!".to_string()
        } else {
            "\u{2717} Failed!".to_string()
        },
    });

    RsaDemoResult {
        success,
        error: None,
        original_message: orig,
        message_number: fmt_bigint(&message_number),
        key_pair: Some(RsaKeyPairResult {
            n: fmt_bigint(&n),
            e: fmt_bigint(&key_pair.public_key.e),
            d: fmt_bigint(&key_pair.private_key.d),
            p: fmt_bigint(&p),
            q: fmt_bigint(&q),
            phi_n: fmt_bigint(&phi_n),
        }),
        ciphertext: fmt_bigint(&ciphertext),
        decrypted_number: fmt_bigint(&decrypted_number),
        decrypted_text,
        steps,
        blocks: vec![],
    }
}
// ============================================================================
// SHA-256 WASM Functions
// ============================================================================

#[wasm_bindgen]
pub fn sha256_demo_text(text: &str) -> String {
    to_json(&run_sha256_demo_internal(Some(text.to_string()), text.as_bytes()))
}

#[wasm_bindgen]
pub fn sha256_demo_bytes(bytes: &[u8]) -> String {
    to_json(&run_sha256_demo_internal(None, bytes))
}

fn run_sha256_demo_internal(message_text: Option<String>, message_bytes: &[u8]) -> Sha256DemoResult {
    let mut steps = Vec::new();

    steps.push(Sha256Step {
        step_number: 1,
        title: "Initial Hash Values H\u{2080}\u{2013}H\u{2087} (FIPS 180-4 \u{00a7}5.3.3)".to_string(),
        description: "Eight 32-bit words derived from the fractional parts of the square roots of the first 8 primes. Nothing-up-my-sleeve construction: the constants are publicly verifiable and not chosen to create a backdoor.".to_string(),
        data: vec![
            format!("H\u{2080} = 0x{:08x} (\u{221a}2)", INITIAL_HASH[0]),
            format!("H\u{2081} = 0x{:08x} (\u{221a}3)", INITIAL_HASH[1]),
            format!("H\u{2082} = 0x{:08x} (\u{221a}5)", INITIAL_HASH[2]),
            format!("H\u{2083} = 0x{:08x} (\u{221a}7)", INITIAL_HASH[3]),
            format!("H\u{2084} = 0x{:08x} (\u{221a}11)", INITIAL_HASH[4]),
            format!("H\u{2085} = 0x{:08x} (\u{221a}13)", INITIAL_HASH[5]),
            format!("H\u{2086} = 0x{:08x} (\u{221a}17)", INITIAL_HASH[6]),
            format!("H\u{2087} = 0x{:08x} (\u{221a}19)", INITIAL_HASH[7]),
        ],
    });

    let processed = preprocess_message(message_bytes);
    steps.push(Sha256Step {
        step_number: 2,
        title: "Message Padding (FIPS 180-4 \u{00a7}5.1.1)".to_string(),
        description: format!(
            "Append bit 1, then zero bits until length \u{2261} 448 (mod 512), then 64-bit big-endian original length. Result: {} bytes in {} block(s) of 512 bits.",
            processed.blocks.len() * 64,
            processed.blocks.len()
        ),
        data: vec![
            format!("Original: {:02x?}", message_bytes),
            format!(
                "Original length: {} bytes = {} bits",
                message_bytes.len(),
                message_bytes.len() * 8
            ),
            format!("Padded to {} blocks \u{00d7} 512 bits", processed.blocks.len()),
        ],
    });

    if !processed.blocks.is_empty() {
        steps.push(Sha256Step {
            step_number: 3,
            title: "Message Schedule W[0..15] (FIPS 180-4 \u{00a7}6.2.2)".to_string(),
            description: "First 16 of 64 words: message bytes packed big-endian into 32-bit words. W[16..63] extend via \u{03c3}\u{2081}(W[i-2]) + W[i-7] + \u{03c3}\u{2080}(W[i-15]) + W[i-16].".to_string(),
            data: processed.blocks[0]
                .iter()
                .enumerate()
                .map(|(i, word)| format!("W[{:2}] = 0x{:08x}", i, word))
                .collect(),
        });
    }

    let mut hash = INITIAL_HASH;

    for (i, block) in processed.blocks.iter().enumerate() {
        hash = compress_block(hash, block, false);

        steps.push(Sha256Step {
            step_number: (4 + i) as u32,
            title: format!("Compression Function \u{00a7}6.2.2 \u{2014} Block {}", i + 1),
            description: format!(
                "64 rounds: T\u{2081}=h+\u{03a3}\u{2081}(e)+Ch(e,f,g)+K[t]+W[t], T\u{2082}=\u{03a3}\u{2080}(a)+Maj(a,b,c); rotate working variables; add to H[\u{2080}..\u{2087}]. Block {} of {}.",
                i + 1, processed.blocks.len()
            ),
            data: hash
                .iter()
                .enumerate()
                .map(|(j, word)| format!("H[{}] = 0x{:08x}", j, word))
                .collect(),
        });
    }

    let final_hash = words_to_hex(&hash);

    steps.push(Sha256Step {
        step_number: (4 + processed.blocks.len()) as u32,
        title: "256-bit Digest (FIPS 180-4 \u{00a7}6.2.2)".to_string(),
        description: "Concatenate final H\u{2080}\u{2016}H\u{2081}\u{2016}\u{22ef}\u{2016}H\u{2087} (8 \u{00d7} 32 bits = 256 bits). One-way: no algorithm is known to recover the input or find a second input with the same digest.".to_string(),
        data: vec![final_hash.clone()],
    });

    Sha256DemoResult {
        success: true,
        error: None,
        original_message: message_text.unwrap_or_else(|| hex::encode(message_bytes)),
        message_bytes: message_bytes.to_vec(),
        hash: final_hash,
        hash_words: hash.iter().map(|w| format!("0x{:08x}", w)).collect(),
        steps,
    }
}

// ============================================================================
// Keccak-256 Types
// ============================================================================

#[derive(Serialize, Deserialize)]
pub struct Keccak256Step {
    pub step_number: u32,
    pub title: String,
    pub description: String,
    pub data: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Keccak256DemoResult {
    pub success: bool,
    pub error: Option<String>,
    pub original_message: String,
    pub hash: String,
    pub steps: Vec<Keccak256Step>,
}

// ============================================================================
// Keccak-256 WASM Functions
// ============================================================================

#[wasm_bindgen]
pub fn keccak256_demo_text(text: &str) -> String {
    if text.is_empty() {
        return to_json(&Keccak256DemoResult {
            success: false,
            error: Some("Please enter a message".to_string()),
            original_message: String::new(),
            hash: String::new(),
            steps: vec![],
        });
    }
    let (hash_bytes, raw_steps) = keccak256_with_steps(text.as_bytes());
    let steps = raw_steps
        .into_iter()
        .map(|s| Keccak256Step {
            step_number: s.step_number,
            title: s.title,
            description: s.description,
            data: s.data,
        })
        .collect();
    to_json(&Keccak256DemoResult {
        success: true,
        error: None,
        original_message: text.to_string(),
        hash: hex::encode(hash_bytes),
        steps,
    })
}

// ============================================================================
// ECC WASM Functions
// ============================================================================

#[wasm_bindgen]
pub fn ecc_demo_secp256k1(private_key_hex: &str) -> String {
    to_json(&run_ecc_secp256k1_internal(private_key_hex))
}

fn run_ecc_secp256k1_internal(private_key_hex: &str) -> EccDemoResult {
    let params = secp256k1();
    let mut steps = Vec::new();

    let keypair = match keypair_from_hex(private_key_hex, &params) {
        Ok(kp) => kp,
        Err(e) => return ecc_error(e),
    };

    let key_hex = format!("{:0>64}", keypair.private_key.to_str_radix(16));
    steps.push(EccStep {
        step_number: 1,
        title: "Private Key".to_string(),
        description: "Parse and range-check k \u{2208} [1, n-1]".to_string(),
        formula: format!("k = 0x{}", key_hex),
        result: format!("valid ({} bits)", keypair.private_key.bits()),
    });

    steps.push(EccStep {
        step_number: 2,
        title: "Short Weierstrass Curve E(\u{1d53d}\u{209a})".to_string(),
        description: "secp256k1 (SECG SEC 2 v2.0): E: y\u{00b2} \u{2261} x\u{00b3} + 7 (mod p) over prime field \u{1d53d}\u{209a}. Used in Bitcoin (BIP-340) and Ethereum (EIP-155) for ECDSA and Schnorr signatures.".to_string(),
        formula: format!("p = 0x{}", params.p.to_str_radix(16)),
        result: "a = 0, b = 7".to_string(),
    });

    steps.push(EccStep {
        step_number: 3,
        title: "Base Point G \u{2208} E(\u{1d53d}\u{209a})".to_string(),
        description: "SECG-standardised generator with prime order n = #E(\u{1d53d}\u{209a}). Every non-identity point on secp256k1 is a multiple of G, so \u{27e8}G\u{27e9} = E(\u{1d53d}\u{209a}).".to_string(),
        formula: format!("Gx = 0x{:0>64}", params.g.x.to_str_radix(16)),
        result: format!("Gy = 0x{:0>64}", params.g.y.to_str_radix(16)),
    });

    let bit_count = keypair.private_key.bits();
    steps.push(EccStep {
        step_number: 4,
        title: "Scalar Multiplication Q = k\u{00b7}G".to_string(),
        description: format!(
            "Double-and-add (binary method) over {}-bit scalar: {} point doublings, up to {} point additions in E(\u{1d53d}\u{209a}). Security rests on the ECDLP: given Q and G, recovering k is computationally infeasible.",
            bit_count, bit_count, bit_count
        ),
        formula: "For each bit i (LSB\u{2192}MSB): if k\u{1d62}=1 then R\u{2190}R+T; T\u{2190}2T".to_string(),
        result: format!("{} iterations completed", bit_count),
    });

    match &keypair.public_key {
        CurvePoint::Infinity => ecc_error("scalar multiplication produced point at infinity".to_string()),
        CurvePoint::Finite(p) => {
            let x_hex = format!("{:0>64}", p.x.to_str_radix(16));
            let y_hex = format!("{:0>64}", p.y.to_str_radix(16));
            let prefix = if p.y.bit(0) { "03" } else { "02" };

            steps.push(EccStep {
                step_number: 5,
                title: "Public Key Encoding (SEC 1 v2.0)".to_string(),
                description: "Compressed point (33 bytes): prefix 02/03 encodes parity of y, followed by x. Uncompressed (65 bytes): prefix 04, x, y. SEC 1 \u{00a7}2.3.3.".to_string(),
                formula: format!("Q = (0x{}..., 0x{}...)", &x_hex[..8], &y_hex[..8]),
                result: format!("compressed: {}{}...", prefix, &x_hex[..16]),
            });

            EccDemoResult {
                success: true,
                error: None,
                key_pair: Some(EccKeyPairResult {
                    private_key: key_hex,
                    public_key_x: x_hex.clone(),
                    public_key_y: y_hex.clone(),
                    public_key_compressed: Some(format!("{}{}", prefix, x_hex)),
                    public_key_uncompressed: Some(format!("04{}{}", x_hex, y_hex)),
                    curve: params.name.clone(),
                }),
                steps,
            }
        }
    }
}

// Counts all points on E: y²≡x³+ax+b (mod p) using Euler's criterion — O(p·log p).
// Restricted to p ≤ 65521 (largest prime < 2¹⁶) so it stays fast in WASM.
fn count_curve_points(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
    use num_traits::ToPrimitive;
    let p64 = p.to_u64().expect("p exceeds u64");
    let a64 = a.to_u64().unwrap_or(0);
    let b64 = b.to_u64().unwrap_or(0);

    let mod_pow = |mut base: u64, mut exp: u64, modulus: u64| -> u64 {
        if modulus == 1 { return 0; }
        let mut result = 1u64;
        base %= modulus;
        while exp > 0 {
            if exp & 1 == 1 { result = result.wrapping_mul(base) % modulus; }
            exp >>= 1;
            base = base.wrapping_mul(base) % modulus;
        }
        result
    };

    let mut count = 1u64; // point at infinity
    for x in 0..p64 {
        let x2 = x.wrapping_mul(x) % p64;
        let x3 = x2.wrapping_mul(x) % p64;
        let rhs = (x3.wrapping_add(a64.wrapping_mul(x)).wrapping_add(b64)) % p64;
        if rhs == 0 {
            count += 1;
        } else if mod_pow(rhs, (p64 - 1) / 2, p64) == 1 {
            count += 2;
        }
    }
    BigUint::from(count)
}

fn parse_small_uint(s: &str) -> Result<BigUint, String> {
    let s = s.trim();
    BigUint::parse_bytes(s.as_bytes(), 10)
        .ok_or_else(|| format!("'{}' is not a valid non-negative integer", s))
}

#[wasm_bindgen]
pub fn ecc_demo_weierstrass(k: &str, a: &str, b: &str, p: &str, gx: &str, gy: &str) -> String {
    let p_val = match parse_small_uint(p) {
        Ok(v) => v,
        Err(e) => return to_json(&ecc_error(e)),
    };
    let a_val = match parse_small_uint(a) {
        Ok(v) => v,
        Err(e) => return to_json(&ecc_error(e)),
    };
    let b_val = match parse_small_uint(b) {
        Ok(v) => v,
        Err(e) => return to_json(&ecc_error(e)),
    };
    let gx_val = match parse_small_uint(gx) {
        Ok(v) => v,
        Err(e) => return to_json(&ecc_error(e)),
    };
    let gy_val = match parse_small_uint(gy) {
        Ok(v) => v,
        Err(e) => return to_json(&ecc_error(e)),
    };
    let k_val = match parse_small_uint(k) {
        Ok(v) => v,
        Err(e) => return to_json(&ecc_error(e)),
    };
    to_json(&run_ecc_weierstrass_internal(k_val, a_val, b_val, p_val, gx_val, gy_val))
}

fn run_ecc_weierstrass_internal(
    k: BigUint,
    a: BigUint,
    b: BigUint,
    p: BigUint,
    gx: BigUint,
    gy: BigUint,
) -> EccDemoResult {
    use num_traits::{ToPrimitive, Zero};
    use crate::rsa::math_utils::is_prime;
    use crate::ecc::validation::point_is_on_curve;
    use crate::ecc::types::{AffinePoint, CurveParams};

    if !is_prime(&p) {
        return ecc_error(format!("p = {} is not prime", p));
    }
    if p.to_u64().map(|v| v > 65521).unwrap_or(true) {
        return ecc_error("p must be \u{2264} 65521 for the Weierstrass demo (auto group-order computation is O(p\u{00b7}log p))".to_string());
    }

    // Non-singularity: 4a³ + 27b² ≢ 0 (mod p)
    let four_a3 = BigUint::from(4u32) * &a * &a * &a;
    let twenty7_b2 = BigUint::from(27u32) * &b * &b;
    let discriminant = (four_a3 + twenty7_b2) % &p;
    if discriminant.is_zero() {
        return ecc_error("curve is singular: 4a³ + 27b² ≡ 0 (mod p). Choose different a, b.".to_string());
    }

    let n = count_curve_points(&a, &b, &p);
    let curve_name = format!("E(\u{1d53d}\u{209a}): y\u{00b2}\u{2261}x\u{00b3}+{}x+{} (mod {})", a, b, p);
    let g = AffinePoint { x: gx.clone(), y: gy.clone() };
    let params = CurveParams { p: p.clone(), a: a.clone(), b: b.clone(), g, n: n.clone(), name: curve_name.clone() };

    if !point_is_on_curve(&params.g, &params) {
        return ecc_error(format!("G = ({}, {}) does not lie on the curve y\u{00b2}\u{2261}x\u{00b3}+{}x+{} (mod {})", gx, gy, a, b, p));
    }

    if k.is_zero() || k >= n {
        return ecc_error(format!("k = {} must be in [1, n\u{2212}1] = [1, {}]", k, &n - BigUint::one()));
    }

    let keypair = match crate::ecc::key_generation::keypair_from_bigint(k.clone(), &params) {
        Ok(kp) => kp,
        Err(e) => return ecc_error(e),
    };

    let mut steps = Vec::new();

    steps.push(EccStep {
        step_number: 1,
        title: format!("Short Weierstrass Curve E(\u{1d53d}\u{209a})"),
        description: format!(
            "E: y\u{00b2} \u{2261} x\u{00b3} + ax + b (mod p), p = {}, a = {}, b = {}. Group order n = {} (computed by point enumeration).",
            p, a, b, n
        ),
        formula: format!("G = ({}, {}), n = {}", gx, gy, n),
        result: format!("k = {}", k),
    });

    let (result, scalar_steps) = scalar_mul_with_steps(&keypair.private_key, &params.g, &params);

    for step in &scalar_steps {
        let op_desc = if step.bit == 1 {
            "k\u{1d62}=1: R \u{2190} R + T (point addition in E(\u{1d53d}\u{209a})), then T \u{2190} 2T (point doubling)"
        } else {
            "k\u{1d62}=0: R unchanged, T \u{2190} 2T (point doubling only)"
        };
        steps.push(EccStep {
            step_number: step.step + 1,
            title: format!("Double-and-Add: bit {}", step.step),
            description: op_desc.to_string(),
            formula: format!("T = {}", step.addend_before),
            result: format!("R = {}", step.result_after),
        });
    }

    let last = scalar_steps.len() as u32 + 2;
    steps.push(EccStep {
        step_number: last,
        title: "Public Key Q = k\u{00b7}G".to_string(),
        description: format!(
            "Q = k\u{00b7}G where k = {}. Given Q and G, recovering k is the Elliptic Curve Discrete Logarithm Problem (ECDLP).",
            k
        ),
        formula: format!("{} \u{00b7} ({}, {})", k, gx, gy),
        result: point_to_str(&result),
    });

    match &result {
        CurvePoint::Infinity => ecc_error("result is point at infinity".to_string()),
        CurvePoint::Finite(pt) => EccDemoResult {
            success: true,
            error: None,
            key_pair: Some(EccKeyPairResult {
                private_key: k.to_string(),
                public_key_x: pt.x.to_string(),
                public_key_y: pt.y.to_string(),
                public_key_compressed: None,
                public_key_uncompressed: None,
                curve: curve_name,
            }),
            steps,
        },
    }
}

// ============================================================================
// Blockchain
// ============================================================================

#[wasm_bindgen]
pub fn blockchain_create_genesis(hash_algo: &str, difficulty: u32, timestamp: f64) -> String {
    let result = create_genesis(hash_algo, difficulty, timestamp as u64);
    to_json(&result)
}

#[wasm_bindgen]
pub fn blockchain_mine_block(
    chain_json: &str,
    data: &str,
    hash_algo: &str,
    difficulty: u32,
    timestamp: f64,
) -> String {
    let chain: Chain = match serde_json::from_str(chain_json) {
        Ok(c) => c,
        Err(e) => {
            return to_json(&MineBlockResult {
                success: false,
                error: Some(e.to_string()),
                block: None,
                chain: None,
                steps: vec![],
                attempts: 0,
            })
        }
    };
    let result = mine_next_block(chain, data, hash_algo, difficulty, timestamp as u64);
    to_json(&result)
}

#[wasm_bindgen]
pub fn blockchain_validate(chain_json: &str) -> String {
    let chain: Chain = match serde_json::from_str(chain_json) {
        Ok(c) => c,
        Err(e) => {
            return to_json(&serde_json::json!({
                "valid": false,
                "error": e.to_string(),
                "message": "Failed to parse chain JSON"
            }))
        }
    };
    to_json(&validate_chain(&chain))
}

#[wasm_bindgen]
pub fn blockchain_tamper(chain_json: &str, block_index: u32, new_data: &str) -> String {
    let chain: Chain = match serde_json::from_str(chain_json) {
        Ok(c) => c,
        Err(e) => {
            return to_json(&ChainResult {
                success: false,
                error: Some(e.to_string()),
                chain: None,
            })
        }
    };
    to_json(&tamper_block(chain, block_index as usize, new_data))
}

// ── ECDSA signing ─────────────────────────────────────────────────────────────

#[wasm_bindgen]
pub fn ecdsa_sign(private_key_hex: &str, message: &str) -> String {
    use crate::ecc::constants::secp256k1 as secp_params;
    use crate::ecc::key_generation::keypair_from_bigint;
    use sha2::{Digest, Sha256};

    let clean = private_key_hex.trim_start_matches("0x").trim_start_matches("0X");
    let private_key = match BigUint::parse_bytes(clean.as_bytes(), 16) {
        Some(k) => k,
        None => return to_json(&EcdsaSignResult {
            success: false,
            error: Some("Invalid hex private key".to_string()),
            r: None, s: None, public_key_x: None, public_key_y: None, message_hash: None,
        }),
    };

    let params = secp_params();
    if private_key.is_zero() || private_key >= params.n {
        return to_json(&EcdsaSignResult {
            success: false,
            error: Some("Private key must be in [1, n-1]".to_string()),
            r: None, s: None, public_key_x: None, public_key_y: None, message_hash: None,
        });
    }

    let msg_hash: [u8; 32] = Sha256::digest(message.as_bytes()).into();

    let kp = match keypair_from_bigint(private_key.clone(), &params) {
        Ok(k) => k,
        Err(e) => return to_json(&EcdsaSignResult {
            success: false, error: Some(e),
            r: None, s: None, public_key_x: None, public_key_y: None, message_hash: None,
        }),
    };

    match ecdsa_sign_inner(&msg_hash, &private_key, &params) {
        None => to_json(&EcdsaSignResult {
            success: false, error: Some("Signing failed".to_string()),
            r: None, s: None, public_key_x: None, public_key_y: None, message_hash: None,
        }),
        Some(sig) => {
            let (px, py) = match &kp.public_key {
                crate::ecc::types::CurvePoint::Finite(p) => (
                    format!("{:0>64}", hex::encode(p.x.to_bytes_be())),
                    format!("{:0>64}", hex::encode(p.y.to_bytes_be())),
                ),
                _ => ("".to_string(), "".to_string()),
            };
            to_json(&EcdsaSignResult {
                success: true, error: None,
                r: Some(format!("{:0>64}", hex::encode(sig.r.to_bytes_be()))),
                s: Some(format!("{:0>64}", hex::encode(sig.s.to_bytes_be()))),
                public_key_x: Some(px),
                public_key_y: Some(py),
                message_hash: Some(hex::encode(msg_hash)),
            })
        }
    }
}

#[wasm_bindgen]
pub fn ecdsa_verify(pubkey_x_hex: &str, pubkey_y_hex: &str, r_hex: &str, s_hex: &str, message: &str) -> String {
    use crate::ecc::constants::secp256k1 as secp_params;
    use crate::ecc::types::{AffinePoint, CurvePoint, EcdsaSignature};
    use sha2::{Digest, Sha256};

    let parse = |s: &str| -> Option<BigUint> {
        let c = s.trim_start_matches("0x").trim_start_matches("0X");
        BigUint::parse_bytes(c.as_bytes(), 16)
    };

    let (px, py, r, s) = match (parse(pubkey_x_hex), parse(pubkey_y_hex), parse(r_hex), parse(s_hex)) {
        (Some(a), Some(b), Some(c), Some(d)) => (a, b, c, d),
        _ => return to_json(&EcdsaVerifyResult {
            valid: false,
            error: Some("Invalid hex input".to_string()),
            message: "Failed to parse inputs".to_string(),
        }),
    };

    let params = secp_params();
    let pubkey = CurvePoint::Finite(AffinePoint { x: px, y: py });
    let sig = EcdsaSignature { r, s };
    let msg_hash: [u8; 32] = Sha256::digest(message.as_bytes()).into();

    let valid = ecdsa_verify_inner(&msg_hash, &sig, &pubkey, &params);
    to_json(&EcdsaVerifyResult {
        valid,
        error: None,
        message: if valid {
            "Signature is valid — the message was signed by the owner of this public key.".to_string()
        } else {
            "Signature is invalid — message or public key does not match.".to_string()
        },
    })
}
