use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

pub struct SchnorrSignature {
    pub r: BigUint,
    pub s: BigUint,
}

#[derive(Serialize, Deserialize)]
pub struct SchnorrStep {
    pub step_number: u32,
    pub title: String,
    pub description: String,
    pub formula: String,
    pub result: String,
}

#[derive(Serialize, Deserialize)]
pub struct SchnorrSignResult {
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
    pub message_hash: Option<String>,
    pub steps: Vec<SchnorrStep>,
}

#[derive(Serialize, Deserialize)]
pub struct SchnorrVerifyResult {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub message: String,
}
