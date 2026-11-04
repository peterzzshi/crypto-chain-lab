use encryption_demo::bls::bls::{aggregate_signatures, sign, verify, verify_aggregate};

fn privkey(byte: u8) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[31] = byte;
    k
}

#[test]
fn sign_returns_none_for_zero_privkey() {
    assert!(sign(&[0u8; 32], b"hello").is_none());
}

#[test]
fn sign_and_verify_roundtrip() {
    let sk = privkey(1);
    let (pk, sig) = sign(&sk, b"test message").unwrap();
    assert!(verify(&pk, &sig, b"test message"));
}

#[test]
fn verify_rejects_wrong_message() {
    let sk = privkey(2);
    let (pk, sig) = sign(&sk, b"message A").unwrap();
    assert!(!verify(&pk, &sig, b"message B"));
}

#[test]
fn verify_rejects_wrong_pubkey() {
    let sk1 = privkey(3);
    let sk2 = privkey(4);
    let (_, sig) = sign(&sk1, b"hello").unwrap();
    let (pk2, _) = sign(&sk2, b"hello").unwrap();
    assert!(!verify(&pk2, &sig, b"hello"));
}

#[test]
fn aggregate_two_signatures_verify() {
    let msg = b"aggregate test";
    let sk1 = privkey(5);
    let sk2 = privkey(6);
    let (pk1, sig1) = sign(&sk1, msg).unwrap();
    let (pk2, sig2) = sign(&sk2, msg).unwrap();

    let agg_sig = aggregate_signatures(&[sig1, sig2]).unwrap();
    assert!(verify_aggregate(&[pk1, pk2], msg, &agg_sig));
}

#[test]
fn aggregate_three_signatures_verify() {
    let msg = b"triple aggregate";
    let keys: Vec<_> = (7u8..10).collect();
    let mut pks = Vec::new();
    let mut sigs = Vec::new();
    for &b in &keys {
        let (pk, sig) = sign(&privkey(b), msg).unwrap();
        pks.push(pk);
        sigs.push(sig);
    }
    let agg_sig = aggregate_signatures(&sigs).unwrap();
    assert!(verify_aggregate(&pks, msg, &agg_sig));
}

#[test]
fn aggregate_verify_rejects_wrong_message() {
    let msg = b"correct message";
    let sk1 = privkey(10);
    let sk2 = privkey(11);
    let (pk1, sig1) = sign(&sk1, msg).unwrap();
    let (pk2, sig2) = sign(&sk2, msg).unwrap();
    let agg_sig = aggregate_signatures(&[sig1, sig2]).unwrap();
    assert!(!verify_aggregate(&[pk1, pk2], b"wrong message", &agg_sig));
}

#[test]
fn aggregate_empty_returns_none() {
    assert!(aggregate_signatures(&[]).is_none());
}

#[test]
fn different_privkeys_produce_different_pubkeys() {
    let (pk1, _) = sign(&privkey(20), b"x").unwrap();
    let (pk2, _) = sign(&privkey(21), b"x").unwrap();
    assert_ne!(pk1, pk2);
}
