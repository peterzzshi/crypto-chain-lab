use encryption_demo::ecc::constants::secp256k1;
use encryption_demo::ecc::key_generation::keypair_from_hex;
use encryption_demo::ecc::types::CurvePoint;

fn derive_pubkey_native(private_key_hex: &str) -> (String, String) {
    let params = secp256k1();
    let keypair = keypair_from_hex(private_key_hex, &params).expect("valid key");
    match keypair.public_key {
        CurvePoint::Finite(p) => (
            format!("{:0>64}", p.x.to_str_radix(16)),
            format!("{:0>64}", p.y.to_str_radix(16)),
        ),
        CurvePoint::Infinity => panic!("got point at infinity"),
    }
}

fn derive_pubkey_reference(private_key_hex: &str) -> (String, String) {
    use k256::SecretKey;
    use k256::elliptic_curve::sec1::ToEncodedPoint;

    let bytes = hex::decode(format!("{:0>64}", private_key_hex)).expect("valid hex");
    let sk = SecretKey::from_slice(&bytes).expect("valid key");
    let pk = sk.public_key();
    let encoded = pk.to_encoded_point(false); // uncompressed: 0x04 || x || y
    let x = hex::encode(&encoded.x().unwrap()[..]);
    let y = hex::encode(&encoded.y().unwrap()[..]);
    (x, y)
}

#[test]
fn secp256k1_k1_equals_generator() {
    let (x, y) = derive_pubkey_native("01");
    let (rx, ry) = derive_pubkey_reference("01");
    assert_eq!(x, rx);
    assert_eq!(y, ry);
}

#[test]
fn secp256k1_k2_matches_reference() {
    let (x, y) = derive_pubkey_native("02");
    let (rx, ry) = derive_pubkey_reference("02");
    assert_eq!(x, rx);
    assert_eq!(y, ry);
}

#[test]
fn secp256k1_k3_matches_reference() {
    let (x, y) = derive_pubkey_native("03");
    let (rx, ry) = derive_pubkey_reference("03");
    assert_eq!(x, rx);
    assert_eq!(y, ry);
}

#[test]
fn secp256k1_k7_matches_reference() {
    let (x, y) = derive_pubkey_native("07");
    let (rx, ry) = derive_pubkey_reference("07");
    assert_eq!(x, rx);
    assert_eq!(y, ry);
}

#[test]
fn secp256k1_large_key_matches_reference() {
    let key = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    let (x, y) = derive_pubkey_native(key);
    let (rx, ry) = derive_pubkey_reference(key);
    assert_eq!(x, rx);
    assert_eq!(y, ry);
}
