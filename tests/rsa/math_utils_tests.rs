use encryption_demo::rsa::math_utils::{is_prime, mod_inverse, mod_pow};
use num_bigint::BigUint;
use num_traits::Zero;

fn b(n: u64) -> BigUint {
    BigUint::from(n)
}

#[test]
fn mod_inverse_exists() {
    let inv = mod_inverse(&b(3), &b(11)).unwrap();
    assert_eq!(inv, b(4));
    assert_eq!((&b(3) * &inv) % b(11), b(1));
}

#[test]
fn mod_inverse_does_not_exist() {
    assert!(mod_inverse(&b(4), &b(8)).is_none());
}

#[test]
fn mod_inverse_of_zero_is_none() {
    assert!(mod_inverse(&BigUint::zero(), &b(11)).is_none());
}

#[test]
fn mod_pow_basic() {
    assert_eq!(mod_pow(&b(2), &b(3), &b(5)), b(3));
}

#[test]
fn mod_pow_large() {
    let result = mod_pow(&b(2), &b(100), &b(1000));
    assert!(result < b(1000));
}

#[test]
fn is_prime_accepts_small_primes() {
    for p in [2u64, 3, 5, 7, 11, 13, 65537] {
        assert!(is_prime(&b(p)), "{p} should be prime");
    }
}

#[test]
fn is_prime_rejects_composites() {
    for n in [0u64, 1, 4, 6, 9, 15, 65536] {
        assert!(!is_prime(&b(n)), "{n} should not be prime");
    }
}

#[test]
fn is_prime_works_for_large_prime() {
    // 2^61 - 1 (Mersenne prime)
    let large = BigUint::from(2u32).pow(61) - BigUint::from(1u32);
    assert!(is_prime(&large));
}
