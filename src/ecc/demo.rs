use super::constants::{secp256k1, weierstrass_demo};
use super::ecdsa::{sign as ecdsa_sign, verify as ecdsa_verify};
use super::key_generation::keypair_from_hex;
use super::math_utils::{point_to_str, scalar_mul_with_steps};
use super::types::{CurvePoint, EcdsaSignature};
use num_bigint::BigUint;
use sha2::{Digest, Sha256};

pub fn run_ecc_demo_secp256k1(private_key_hex: &str) -> Result<(), String> {
    let params = secp256k1();
    let keypair = keypair_from_hex(private_key_hex, &params)?;

    println!("🔑 ECC Key Generation Demo (secp256k1)");
    println!("Private key: 0x{}", private_key_hex.trim_start_matches("0x"));
    println!("Curve: y² = x³ + 7 (mod p)");
    println!("p = 0x{}", params.p.to_str_radix(16));

    println!("\n=== Generator Point G ===");
    println!("  Gx = 0x{:0>64}", params.g.x.to_str_radix(16));
    println!("  Gy = 0x{:0>64}", params.g.y.to_str_radix(16));

    println!("\n=== Scalar Multiplication Q = k·G ===");
    println!("  Performing {}-bit double-and-add...", keypair.private_key.bits());

    match &keypair.public_key {
        CurvePoint::Infinity => return Err("scalar multiplication produced point at infinity".to_string()),
        CurvePoint::Finite(p) => {
            let x_hex = format!("{:0>64}", p.x.to_str_radix(16));
            let y_hex = format!("{:0>64}", p.y.to_str_radix(16));
            let prefix = if p.y.bit(0) { "03" } else { "02" };
            println!("\n=== Public Key Q ===");
            println!("  Qx = 0x{}", x_hex);
            println!("  Qy = 0x{}", y_hex);
            println!("\n=== Encoding ===");
            println!("  Compressed:   {}{}", prefix, x_hex);
            println!("  Uncompressed: 04{}{}", x_hex, y_hex);
        }
    }

    Ok(())
}

pub fn run_ecc_demo_weierstrass(k: u32) -> Result<(), String> {
    let params = weierstrass_demo();
    let private_key = BigUint::from(k);
    super::validation::validate_private_key(&private_key, &params)?;

    println!("🔑 ECC Key Generation Demo ({})", params.name);
    println!("Private key k = {}", k);
    println!("Curve: y² = x³ + x + 6 (mod {})", params.p);
    println!("Generator: G = ({}, {})", params.g.x, params.g.y);
    println!("Curve order: n = {}", params.n);

    let (result, steps) = scalar_mul_with_steps(&private_key, &params.g, &params);

    println!("\n=== Scalar Multiplication: Q = {} · G ===", k);
    for step in &steps {
        println!(
            "  Step {} (bit={}): {} | addend={} → result={}",
            step.step, step.bit, step.operation, step.addend_before, step.result_after
        );
    }

    println!("\n=== Public Key Q ===");
    println!("  Q = {}", point_to_str(&result));

    match &result {
        CurvePoint::Infinity => println!("  (point at infinity — unexpected)"),
        CurvePoint::Finite(p) => {
            println!("  {} · ({}, {}) = ({}, {})", k, params.g.x, params.g.y, p.x, p.y);
        }
    }

    Ok(())
}

pub fn run_ecdsa_demo(private_key_hex: &str, message: &str) -> Result<(), String> {
    let params = secp256k1();
    let keypair = keypair_from_hex(private_key_hex, &params)?;

    let hash: [u8; 32] = Sha256::digest(message.as_bytes()).into();

    let sig = ecdsa_sign(&hash, &keypair.private_key, &params)
        .ok_or("signing failed (r or s was zero)")?;

    let pub_pt = match &keypair.public_key {
        CurvePoint::Finite(p) => p,
        CurvePoint::Infinity => return Err("public key is point at infinity".to_string()),
    };

    println!("✍️  ECDSA Sign / Verify Demo (secp256k1 + RFC 6979)");
    println!("Private key : 0x{}", private_key_hex.trim_start_matches("0x"));
    println!("Message     : \"{}\"", message);
    println!("SHA-256(msg): {}", hex::encode(hash));
    println!("\n=== Public Key ===");
    println!("  Qx = 0x{:0>64}", pub_pt.x.to_str_radix(16));
    println!("  Qy = 0x{:0>64}", pub_pt.y.to_str_radix(16));
    println!("\n=== Signature (r, s) ===");
    println!("  r  = 0x{:0>64}", sig.r.to_str_radix(16));
    println!("  s  = 0x{:0>64}", sig.s.to_str_radix(16));

    let valid = ecdsa_verify(&hash, &sig, &keypair.public_key, &params);
    println!("\n=== Verification ===");
    println!("  {} (same key + message)", if valid { "✅ VALID" } else { "❌ INVALID" });

    // Demonstrate that tampering breaks verification
    let bad_sig = EcdsaSignature {
        r: sig.r.clone(),
        s: (&sig.s + BigUint::from(1u32)) % &params.n,
    };
    let tampered = ecdsa_verify(&hash, &bad_sig, &keypair.public_key, &params);
    println!("  {} (s incremented by 1)", if tampered { "✅ VALID" } else { "❌ INVALID — tampered s rejected" });

    Ok(())
}

pub fn run_ecc_demo(key: &str, curve: &str) -> Result<(), String> {
    match curve {
        "weierstrass" => key
            .parse::<u32>()
            .map_err(|_| "Weierstrass demo curve key must be a positive integer ≤ 13".to_string())
            .and_then(run_ecc_demo_weierstrass),
        _ => run_ecc_demo_secp256k1(key),
    }
}
