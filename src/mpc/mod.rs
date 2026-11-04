#[allow(clippy::module_inception)]
pub mod mpc;
pub mod types;

pub use mpc::{reconstruct, split, Share};
pub use types::{MpcShareInfo, MpcSplitDemoResult};
