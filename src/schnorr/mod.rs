#[allow(clippy::module_inception)]
pub mod schnorr;
pub mod types;

pub use schnorr::{has_even_y, lift_x, pubkey_x_from_privkey, sign, tagged_hash, verify};
pub use types::{SchnorrSignResult, SchnorrSignature, SchnorrStep, SchnorrVerifyResult};
