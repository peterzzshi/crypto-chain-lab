use encryption_demo::rsa::key_generation::generate_keypair;
use encryption_demo::rsa::math_utils::is_prime;
use num_bigint::BigUint;

fn b(n: u64) -> BigUint {
    BigUint::from(n)
}

#[test]
fn is_prime_rejects_composites() {
    for n in [0u64, 1, 4, 6, 9] {
        assert!(!is_prime(&b(n)));
    }
}

#[test]
fn is_prime_accepts_primes() {
    for p in [2u64, 3, 5, 7, 11, 65537] {
        assert!(is_prime(&b(p)));
    }
}

#[test]
fn valid_primes_produce_keypair() {
    assert!(generate_keypair(&b(3), &b(11)).is_some());
}

#[test]
fn any_input_to_generate_keypair_does_not_panic() {
    let _ = generate_keypair(&b(5), &b(5));
    let _ = generate_keypair(&b(4), &b(7));
}
