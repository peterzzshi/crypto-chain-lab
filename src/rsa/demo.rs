use super::encryption::{decrypt, encrypt};
use super::key_generation::generate_keypair;
use super::text_encoding::{number_to_text, text_to_number};
use super::validation::{is_valid_message_size, validate_primes};
use num_bigint::BigUint;
use num_traits::One;

fn parse_prime_str(s: &str) -> Result<BigUint, String> {
    let s = s.trim();
    let (digits, radix) = if s.starts_with("0x") || s.starts_with("0X") {
        (&s[2..], 16u32)
    } else {
        (s, 10u32)
    };
    BigUint::parse_bytes(digits.as_bytes(), radix).ok_or_else(|| format!("'{}' is not a valid integer", s))
}

fn parse_message_str(s: &str) -> BigUint {
    let s = s.trim();
    let (digits, radix) = if s.starts_with("0x") || s.starts_with("0X") {
        (&s[2..], 16u32)
    } else {
        (s, 10u32)
    };
    BigUint::parse_bytes(digits.as_bytes(), radix).unwrap_or_default()
}

fn run_rsa_demo_internal(message_text: Option<&str>, message_number: BigUint, p: BigUint, q: BigUint) {
    if let Some(text) = message_text {
        println!("RSA Text Encryption Demo");
        println!("Text: \"{}\" -> BigUint: {}", text, message_number);
    } else {
        println!("RSA Number Encryption Demo");
        println!("Message: {}", message_number);
    }
    println!("Primes: p={}, q={}", p, q);

    if let Err(e) = validate_primes(&p, &q) {
        eprintln!("Error: {}", e);
        return;
    }

    let key_pair = match generate_keypair(&p, &q) {
        Some(kp) => kp,
        None => {
            eprintln!("Error: Could not find a valid public exponent. Try different primes.");
            return;
        }
    };

    if !is_valid_message_size(&message_number, &key_pair.public_key.n) {
        eprintln!(
            "Error: Message must be smaller than modulus n={}",
            key_pair.public_key.n
        );
        return;
    }

    let phi_n = (p.clone() - BigUint::one()) * (q.clone() - BigUint::one());
    println!(
        "n = {}, e = {}, d = {}, phi_n = {}",
        key_pair.public_key.n, key_pair.public_key.e, key_pair.private_key.d, phi_n
    );

    let ciphertext = encrypt(&message_number, &key_pair.public_key);
    println!("Encrypted: {}", ciphertext);

    let decrypted_number = decrypt(&ciphertext, &key_pair.private_key);
    println!("Decrypted: {}", decrypted_number);

    let success = if let Some(orig_text) = message_text {
        let decrypted_text = number_to_text(&decrypted_number);
        println!("Original: {}, Decrypted: {}", orig_text, decrypted_text);
        orig_text == decrypted_text.as_str() && message_number == decrypted_number
    } else {
        message_number == decrypted_number
    };

    if success {
        println!("Success!");
    } else {
        println!("Failed!");
    }
}

pub fn run_rsa_demo(message: &str, p: &str, q: &str) {
    let p = match parse_prime_str(p) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            return;
        }
    };
    let q = match parse_prime_str(q) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            return;
        }
    };
    run_rsa_demo_internal(None, parse_message_str(message), p, q);
}

pub fn run_rsa_demo_text(text: &str, p: &str, q: &str) {
    let p = match parse_prime_str(p) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            return;
        }
    };
    let q = match parse_prime_str(q) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            return;
        }
    };
    match text_to_number(text) {
        Some(number) => run_rsa_demo_internal(Some(text), number, p, q),
        None => eprintln!("Error: Empty text."),
    }
}
