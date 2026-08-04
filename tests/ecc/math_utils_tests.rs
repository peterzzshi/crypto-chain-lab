use encryption_demo::ecc::math_utils::field_inv;
use num_bigint::BigUint;
use num_traits::{One, Zero};

#[test]
fn field_inv_of_nonzero_is_multiplicative_inverse() {
    let p = BigUint::from(11u32);
    // 3 * 4 = 12 ≡ 1 (mod 11)
    let inv = field_inv(&BigUint::from(3u32), &p).unwrap();
    assert_eq!(inv, BigUint::from(4u32));
}

#[test]
fn field_inv_of_zero_returns_none() {
    let p = BigUint::from(11u32);
    assert!(field_inv(&BigUint::zero(), &p).is_none());
}

#[test]
fn field_inv_roundtrip() {
    let p = BigUint::from(11u32);
    for a in 1u32..11 {
        let a_big = BigUint::from(a);
        let inv = field_inv(&a_big, &p).unwrap();
        let product = (&a_big * &inv) % &p;
        assert_eq!(
            product,
            BigUint::one(),
            "a={} inv={} not a valid inverse mod 11",
            a,
            inv
        );
    }
}
