use super::math_utils::scalar_mul;
use super::types::{CurveParams, EccKeyPair};
use super::validation::validate_private_key;
use num_bigint::BigUint;

pub fn keypair_from_hex(hex: &str, params: &CurveParams) -> Result<EccKeyPair, String> {
    let private_key = parse_hex(hex)?;
    validate_private_key(&private_key, params)?;
    let public_key = scalar_mul(&private_key, &params.g, params);
    Ok(EccKeyPair {
        private_key,
        public_key,
    })
}

pub fn keypair_from_scalar(k: u32, params: &CurveParams) -> Result<EccKeyPair, String> {
    let private_key = BigUint::from(k);
    validate_private_key(&private_key, params)?;
    let public_key = scalar_mul(&private_key, &params.g, params);
    Ok(EccKeyPair {
        private_key,
        public_key,
    })
}

pub fn keypair_from_bigint(k: BigUint, params: &CurveParams) -> Result<EccKeyPair, String> {
    validate_private_key(&k, params)?;
    let public_key = scalar_mul(&k, &params.g, params);
    Ok(EccKeyPair { private_key: k, public_key })
}

fn parse_hex(hex: &str) -> Result<BigUint, String> {
    let clean = hex.trim_start_matches("0x").trim_start_matches("0X");
    if clean.is_empty() {
        return Err("private key is empty".to_string());
    }
    BigUint::parse_bytes(clean.as_bytes(), 16).ok_or_else(|| format!("invalid hex private key: '{}'", hex))
}
