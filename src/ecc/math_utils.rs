use super::types::{AffinePoint, CurveParams, CurvePoint, ScalarMulStep};
use num_bigint::BigUint;
use num_traits::Zero;

fn mod_sub(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
    let a = a % p;
    let b = b % p;
    if a >= b { a - b } else { p - b + a }
}

fn field_mul(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
    (a * b) % p
}

// Fermat's little theorem: a^(p-2) mod p — valid only when p is prime
pub fn field_inv(a: &BigUint, p: &BigUint) -> Option<BigUint> {
    if a.is_zero() {
        return None;
    }
    let exp = p - BigUint::from(2u32);
    Some(a.modpow(&exp, p))
}

fn apply_double_formula(point: &AffinePoint, params: &CurveParams) -> Option<AffinePoint> {
    let x_sq = field_mul(&point.x, &point.x, &params.p);
    let three_x_sq = (BigUint::from(3u32) * x_sq) % &params.p;
    let numerator = (&three_x_sq + &params.a) % &params.p;
    let two_y = (BigUint::from(2u32) * &point.y) % &params.p;
    let lambda = field_mul(&numerator, &field_inv(&two_y, &params.p)?, &params.p);
    let lambda_sq = field_mul(&lambda, &lambda, &params.p);
    let two_x = (BigUint::from(2u32) * &point.x) % &params.p;
    let x3 = mod_sub(&lambda_sq, &two_x, &params.p);
    let y3 = mod_sub(
        &field_mul(&lambda, &mod_sub(&point.x, &x3, &params.p), &params.p),
        &point.y,
        &params.p,
    );
    Some(AffinePoint { x: x3, y: y3 })
}

fn apply_add_formula(a: &AffinePoint, b: &AffinePoint, params: &CurveParams) -> Option<AffinePoint> {
    let dy = mod_sub(&b.y, &a.y, &params.p);
    let dx = mod_sub(&b.x, &a.x, &params.p);
    let lambda = field_mul(&dy, &field_inv(&dx, &params.p)?, &params.p);
    let lambda_sq = field_mul(&lambda, &lambda, &params.p);
    let x3 = mod_sub(&mod_sub(&lambda_sq, &a.x, &params.p), &b.x, &params.p);
    let y3 = mod_sub(
        &field_mul(&lambda, &mod_sub(&a.x, &x3, &params.p), &params.p),
        &a.y,
        &params.p,
    );
    Some(AffinePoint { x: x3, y: y3 })
}

pub fn point_double(point: &AffinePoint, params: &CurveParams) -> CurvePoint {
    if point.y.is_zero() {
        return CurvePoint::Infinity;
    }
    apply_double_formula(point, params)
        .map(CurvePoint::Finite)
        .unwrap_or(CurvePoint::Infinity)
}

pub fn point_add(p1: &CurvePoint, p2: &CurvePoint, params: &CurveParams) -> CurvePoint {
    match (p1, p2) {
        (CurvePoint::Infinity, _) => p2.clone(),
        (_, CurvePoint::Infinity) => p1.clone(),
        (CurvePoint::Finite(a), CurvePoint::Finite(b)) if a.x == b.x => {
            if a.y == b.y {
                point_double(a, params)
            } else {
                CurvePoint::Infinity
            }
        }
        (CurvePoint::Finite(a), CurvePoint::Finite(b)) => apply_add_formula(a, b, params)
            .map(CurvePoint::Finite)
            .unwrap_or(CurvePoint::Infinity),
    }
}

pub fn scalar_mul(k: &BigUint, point: &AffinePoint, params: &CurveParams) -> CurvePoint {
    let mut result = CurvePoint::Infinity;
    let mut addend = CurvePoint::Finite(point.clone());
    let mut k = k.clone();

    while !k.is_zero() {
        if k.bit(0) {
            result = point_add(&result, &addend, params);
        }
        addend = point_add(&addend, &addend, params);
        k >>= 1usize;
    }

    result
}

// Returns (result, steps) — intended for small-parameter educational demos only
pub fn scalar_mul_with_steps(
    k: &BigUint,
    point: &AffinePoint,
    params: &CurveParams,
) -> (CurvePoint, Vec<ScalarMulStep>) {
    let mut result = CurvePoint::Infinity;
    let mut addend = CurvePoint::Finite(point.clone());
    let mut k_copy = k.clone();
    let mut steps = Vec::new();
    let mut step_num = 1u32;

    while !k_copy.is_zero() {
        let bit_set = k_copy.bit(0);
        let addend_str = point_to_str(&addend);

        if bit_set {
            result = point_add(&result, &addend, params);
        }
        addend = point_add(&addend, &addend, params);

        steps.push(ScalarMulStep {
            step: step_num,
            bit: bit_set as u8,
            operation: if bit_set { "double + add" } else { "double" }.to_string(),
            addend_before: addend_str,
            result_after: point_to_str(&result),
        });

        k_copy >>= 1usize;
        step_num += 1;
    }

    (result, steps)
}

pub fn point_to_str(p: &CurvePoint) -> String {
    match p {
        CurvePoint::Infinity => "\u{221e}".to_string(),
        CurvePoint::Finite(a) => format!("({}, {})", a.x, a.y),
    }
}
