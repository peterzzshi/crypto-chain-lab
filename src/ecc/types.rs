use num_bigint::BigUint;

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
