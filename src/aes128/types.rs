use serde::Serialize;

/// 4×4 byte matrix; indexed state[row][col], column-major byte order (FIPS 197 §3.4).
pub type State = [[u8; 4]; 4];
pub type Word = [u8; 4];

#[derive(Serialize)]
pub struct Aes128Step {
    pub step_number: u32,
    pub title: String,
    pub description: String,
    pub state_hex: Vec<String>,
}

#[derive(Serialize)]
pub struct Aes128DemoResult {
    pub success: bool,
    pub error: Option<String>,
    pub plaintext_hex: String,
    pub key_hex: String,
    pub ciphertext_hex: String,
    pub decrypted_hex: String,
    pub steps: Vec<Aes128Step>,
}
