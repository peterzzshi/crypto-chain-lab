use encryption_demo::ecc::constants::secp256k1;
use encryption_demo::mpc::mpc::{reconstruct, split, Share};

fn n() -> num_bigint::BigUint {
    secp256k1().n
}

fn secret() -> num_bigint::BigUint {
    num_bigint::BigUint::parse_bytes(
        b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413F",
        16,
    )
    .unwrap()
}

#[test]
fn split_produces_three_shares() {
    let s = secret();
    let n = n();
    let shares = split(&s, 2, 3, &n).unwrap();
    assert_eq!(shares.len(), 3);
}

#[test]
fn reconstruct_from_shares_1_and_2() {
    let s = secret();
    let n = n();
    let shares = split(&s, 2, 3, &n).unwrap();
    let subset = vec![
        Share { x: shares[0].x.clone(), y: shares[0].y.clone() },
        Share { x: shares[1].x.clone(), y: shares[1].y.clone() },
    ];
    let recovered = reconstruct(&subset, &n).unwrap();
    assert_eq!(recovered, s % &n);
}

#[test]
fn reconstruct_from_shares_1_and_3() {
    let s = secret();
    let n = n();
    let shares = split(&s, 2, 3, &n).unwrap();
    let subset = vec![
        Share { x: shares[0].x.clone(), y: shares[0].y.clone() },
        Share { x: shares[2].x.clone(), y: shares[2].y.clone() },
    ];
    let recovered = reconstruct(&subset, &n).unwrap();
    assert_eq!(recovered, s % &n);
}

#[test]
fn reconstruct_from_shares_2_and_3() {
    let s = secret();
    let n = n();
    let shares = split(&s, 2, 3, &n).unwrap();
    let subset = vec![
        Share { x: shares[1].x.clone(), y: shares[1].y.clone() },
        Share { x: shares[2].x.clone(), y: shares[2].y.clone() },
    ];
    let recovered = reconstruct(&subset, &n).unwrap();
    assert_eq!(recovered, s % &n);
}

#[test]
fn single_share_does_not_reconstruct_secret() {
    let s = secret();
    let n = n();
    let shares = split(&s, 2, 3, &n).unwrap();
    let subset = vec![Share { x: shares[0].x.clone(), y: shares[0].y.clone() }];
    let recovered = reconstruct(&subset, &n).unwrap();
    // With only 1 share and threshold 2, Lagrange at x=0 gives the share value, not the secret
    assert_ne!(recovered, s % &n);
}

#[test]
fn all_three_shares_reconstruct_secret() {
    let s = secret();
    let n = n();
    let shares = split(&s, 2, 3, &n).unwrap();
    let subset: Vec<Share> = shares
        .iter()
        .map(|sh| Share { x: sh.x.clone(), y: sh.y.clone() })
        .collect();
    let recovered = reconstruct(&subset, &n).unwrap();
    assert_eq!(recovered, s % &n);
}

#[test]
fn split_rejects_zero_secret() {
    let n = n();
    let result = split(&num_bigint::BigUint::ZERO, 2, 3, &n);
    assert!(result.is_none());
}

#[test]
fn split_rejects_threshold_larger_than_shares() {
    let n = n();
    let result = split(&secret(), 4, 3, &n);
    assert!(result.is_none());
}

#[test]
fn different_secrets_produce_different_shares() {
    let n = n();
    let s1 = secret();
    let s2 = num_bigint::BigUint::from(42u32);
    let shares1 = split(&s1, 2, 3, &n).unwrap();
    let shares2 = split(&s2, 2, 3, &n).unwrap();
    assert_ne!(shares1[0].y, shares2[0].y);
}
