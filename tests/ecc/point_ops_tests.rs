use encryption_demo::ecc::constants::weierstrass_demo;
use encryption_demo::ecc::math_utils::{point_add, point_double};
use encryption_demo::ecc::types::{AffinePoint, CurvePoint};
use num_bigint::BigUint;

fn pt(x: u32, y: u32) -> CurvePoint {
    CurvePoint::Finite(AffinePoint {
        x: BigUint::from(x),
        y: BigUint::from(y),
    })
}

#[test]
fn adding_infinity_to_point_is_identity() {
    let params = weierstrass_demo();
    let g = pt(2, 7);
    assert_eq!(point_add(&CurvePoint::Infinity, &g, &params), g);
    assert_eq!(point_add(&g, &CurvePoint::Infinity, &params), g);
}

#[test]
fn adding_point_to_its_negation_gives_infinity() {
    // -G on mod 11 is (2, 11-7) = (2, 4)
    let params = weierstrass_demo();
    let g = pt(2, 7);
    let neg_g = pt(2, 4);
    assert_eq!(point_add(&g, &neg_g, &params), CurvePoint::Infinity);
}

#[test]
fn point_double_g_gives_known_result() {
    // 2G = (5, 2) on y²=x³+x+6 mod 11
    let params = weierstrass_demo();
    let g = AffinePoint {
        x: BigUint::from(2u32),
        y: BigUint::from(7u32),
    };
    let doubled = point_double(&g, &params);
    assert_eq!(doubled, pt(5, 2));
}

#[test]
fn point_add_distinct_gives_known_result() {
    // G + 2G = 3G = (8, 3) on y²=x³+x+6 mod 11
    let params = weierstrass_demo();
    let g = pt(2, 7);
    let two_g = pt(5, 2);
    let three_g = point_add(&g, &two_g, &params);
    assert_eq!(three_g, pt(8, 3));
}

#[test]
fn n_times_g_is_point_at_infinity() {
    // Any n*G where n = curve order should be infinity
    use encryption_demo::ecc::math_utils::scalar_mul;
    let params = weierstrass_demo();
    let g = AffinePoint {
        x: BigUint::from(2u32),
        y: BigUint::from(7u32),
    };
    let result = scalar_mul(&params.n.clone(), &g, &params);
    assert_eq!(result, CurvePoint::Infinity);
}
