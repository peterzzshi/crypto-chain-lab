use super::types::{AffinePoint, CurveParams};
use num_bigint::BigUint;
use num_traits::Zero;

pub fn validate_private_key(k: &BigUint, params: &CurveParams) -> Result<(), String> {
    if k.is_zero() {
        return Err("private key cannot be zero".to_string());
    }
    if k >= &params.n {
        return Err(format!(
            "private key must be less than curve order n ({} bits)",
            params.n.bits()
        ));
    }
    Ok(())
}

pub fn point_is_on_curve(point: &AffinePoint, params: &CurveParams) -> bool {
    let y_sq = (&point.y * &point.y) % &params.p;
    let x_cu = (&point.x * &point.x) % &params.p * &point.x % &params.p;
    let ax = (&params.a * &point.x) % &params.p;
    let rhs = (x_cu + ax + &params.b) % &params.p;
    y_sq == rhs
}
