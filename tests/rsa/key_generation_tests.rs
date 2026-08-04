use encryption_demo::rsa::key_generation::generate_keypair;
use num_bigint::BigUint;

fn b(n: u64) -> BigUint {
    BigUint::from(n)
}

#[test]
fn keypair_basic_fields() {
    let keypair = generate_keypair(&b(61), &b(53)).unwrap();
    assert_eq!(keypair.public_key.n, b(61) * b(53));
    assert_eq!(keypair.private_key.n, b(61) * b(53));
}

#[test]
fn keypair_e_is_common_exponent() {
    let keypair = generate_keypair(&b(61), &b(53)).unwrap();
    let common = [3u64, 5, 7, 11, 13, 17, 257, 65537];
    assert!(common.iter().any(|&e| keypair.public_key.e == b(e)));
}

#[test]
fn keypair_ed_product_is_one_mod_phi() {
    let p = b(61);
    let q = b(53);
    let keypair = generate_keypair(&p, &q).unwrap();
    let phi_n = (p - BigUint::from(1u32)) * (q - BigUint::from(1u32));
    let product = (keypair.public_key.e * keypair.private_key.d) % &phi_n;
    assert_eq!(product, BigUint::from(1u32));
}

#[test]
fn generate_keypair_does_not_panic_for_any_inputs() {
    let _ = generate_keypair(&b(2), &b(3));
    let _ = generate_keypair(&b(5), &b(5));
}
