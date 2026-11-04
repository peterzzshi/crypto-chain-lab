use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct MpcShareInfo {
    pub index: u8,
    pub value: String,
}

#[derive(Serialize, Deserialize)]
pub struct MpcSplitDemoResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shares: Option<Vec<MpcShareInfo>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reconstructed_key_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reconstruction_valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_y: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecdsa_r: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecdsa_s: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_valid: Option<bool>,
}
