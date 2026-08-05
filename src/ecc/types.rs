use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq)]
pub struct AffinePoint {
    pub x: BigUint,
    pub y: BigUint,
}

#[derive(Clone, Debug, PartialEq)]
pub enum CurvePoint {
    Infinity,
    Finite(AffinePoint),
}

pub struct CurveParams {
    pub p: BigUint,
    pub a: BigUint,
    pub b: BigUint,
    pub g: AffinePoint,
    pub n: BigUint,
    pub name: String,
}

pub struct EccKeyPair {
    pub private_key: BigUint,
    pub public_key: CurvePoint,
}

pub struct ScalarMulStep {
    pub step: u32,
    pub bit: u8,
    pub operation: String,
    pub addend_before: String,
    pub result_after: String,
}

pub struct EcdsaSignature {
    pub r: BigUint,
    pub s: BigUint,
}

#[derive(Serialize, Deserialize)]
pub struct EcdsaSignResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_y: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_hash: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct EcdsaVerifyResult {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub message: String,
}
