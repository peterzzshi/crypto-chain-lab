use super::types::{AffinePoint, CurveParams};
use num_bigint::BigUint;
use num_traits::Zero;

// Panics only for malformed source-level hex literals — not reachable at runtime
fn hex(s: &str) -> BigUint {
    BigUint::parse_bytes(s.as_bytes(), 16).unwrap()
}

pub fn secp256k1() -> CurveParams {
    CurveParams {
        p: hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"),
        a: BigUint::zero(),
        b: BigUint::from(7u32),
        g: AffinePoint {
            x: hex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
            y: hex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
        },
        n: hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
        name: "secp256k1".to_string(),
    }
}

// Short Weierstrass curve E(𝔽₁₁): y² ≡ x³ + x + 6 (mod 11)
// G = (2, 7), order #E(𝔽₁₁) = 13 (prime). Same form as secp256k1 at human-readable scale.
pub fn weierstrass_demo() -> CurveParams {
    CurveParams {
        p: BigUint::from(11u32),
        a: BigUint::from(1u32),
        b: BigUint::from(6u32),
        g: AffinePoint {
            x: BigUint::from(2u32),
            y: BigUint::from(7u32),
        },
        n: BigUint::from(13u32),
        name: "E(\u{1d53d}\u{2081}\u{2081}): y\u{00b2}\u{2261}x\u{00b3}+x+6".to_string(),
    }
}
