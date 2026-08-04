use encryption_demo::ecc::constants::weierstrass_demo;
use encryption_demo::ecc::key_generation::keypair_from_scalar;
use encryption_demo::ecc::types::CurvePoint;
use num_bigint::BigUint;

#[test]
fn scalar_zero_is_rejected() {
    let params = weierstrass_demo();
    assert!(keypair_from_scalar(0, &params).is_err());
}

#[test]
fn scalar_at_order_is_rejected() {
    let params = weierstrass_demo();
    // n = 13 for the demo curve
    assert!(keypair_from_scalar(13, &params).is_err());
}

#[test]
fn scalar_one_produces_generator() {
    let params = weierstrass_demo();
    let keypair = keypair_from_scalar(1, &params).unwrap();
    match &keypair.public_key {
        CurvePoint::Finite(p) => {
            assert_eq!(p.x, params.g.x);
            assert_eq!(p.y, params.g.y);
        }
        CurvePoint::Infinity => panic!("1*G should not be infinity"),
    }
}

#[test]
fn known_scalar_produces_correct_point() {
    // 2G on y²=x³+x+6 mod 11: G=(2,7), 2G=(5,2)
    let params = weierstrass_demo();
    let keypair = keypair_from_scalar(2, &params).unwrap();
    match &keypair.public_key {
        CurvePoint::Finite(p) => {
            assert_eq!(p.x, BigUint::from(5u32));
            assert_eq!(p.y, BigUint::from(2u32));
        }
        CurvePoint::Infinity => panic!("2*G should not be infinity"),
    }
}
