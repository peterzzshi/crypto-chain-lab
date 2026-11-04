use hex;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use sha2::{Digest, Sha256};

use crate::ecc::math_utils::{point_add, scalar_mul};
use crate::ecc::types::{AffinePoint, CurveParams, CurvePoint};

use super::types::{SchnorrSignature, SchnorrStep};

/// BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg)
pub fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let tag_hash: [u8; 32] = Sha256::digest(tag.as_bytes()).into();
    let mut h = Sha256::new();
    h.update(tag_hash);
    h.update(tag_hash);
    h.update(msg);
    h.finalize().into()
}

fn big_to_bytes32(n: &BigUint) -> [u8; 32] {
    let b = n.to_bytes_be();
    let mut out = [0u8; 32];
    let len = b.len().min(32);
    out[32 - len..].copy_from_slice(&b[b.len() - len..]);
    out
}

fn fmt_hex64(n: &BigUint) -> String {
    format!("{:0>64}", hex::encode(n.to_bytes_be()))
}

pub fn has_even_y(point: &AffinePoint) -> bool {
    &point.y % 2u32 == BigUint::zero()
}

/// Lift x to the secp256k1 curve point with even y (BIP-340 convention).
/// secp256k1: p ≡ 3 (mod 4), so y = (x³ + ax + b)^((p+1)/4) mod p.
pub fn lift_x(x: &BigUint, params: &CurveParams) -> Option<AffinePoint> {
    if x >= &params.p {
        return None;
    }
    let x3 = x.modpow(&BigUint::from(3u32), &params.p);
    let ax = (&params.a * x) % &params.p;
    let y_sq = (x3 + ax + &params.b) % &params.p;
    let exp = (&params.p + BigUint::one()) >> 2; // (p+1)/4 — valid since p ≡ 3 (mod 4)
    let y = y_sq.modpow(&exp, &params.p);
    // verify the square root is correct
    if y.modpow(&BigUint::from(2u32), &params.p) != y_sq {
        return None;
    }
    let y = if &y % 2u32 == BigUint::zero() { y } else { &params.p - y };
    Some(AffinePoint { x: x.clone(), y })
}

/// x-only public key (32 bytes) from private key.
pub fn pubkey_x_from_privkey(privkey: &BigUint, params: &CurveParams) -> Option<BigUint> {
    match scalar_mul(privkey, &params.g, params) {
        CurvePoint::Finite(p) => Some(p.x),
        CurvePoint::Infinity => None,
    }
}

pub fn sign(
    privkey_bytes: &[u8; 32],
    msg: &[u8; 32],
    aux_rand: &[u8; 32],
    params: &CurveParams,
) -> Option<SchnorrSignature> {
    sign_with_steps(privkey_bytes, msg, aux_rand, params).map(|(sig, _)| sig)
}

pub fn sign_with_steps(
    privkey_bytes: &[u8; 32],
    msg: &[u8; 32],
    aux_rand: &[u8; 32],
    params: &CurveParams,
) -> Option<(SchnorrSignature, Vec<SchnorrStep>)> {
    let n = &params.n;
    let d0 = BigUint::from_bytes_be(privkey_bytes) % n;
    if d0.is_zero() {
        return None;
    }

    let p_point = match scalar_mul(&d0, &params.g, params) {
        CurvePoint::Finite(p) => p,
        CurvePoint::Infinity => return None,
    };

    // Negate d if P.y is odd so the public key has even y
    let d = if has_even_y(&p_point) {
        d0.clone()
    } else {
        (n - &d0) % n
    };
    let p_x = big_to_bytes32(&p_point.x);

    // t = d XOR tagged_hash("BIP0340/aux", aux_rand)
    let aux_hash = tagged_hash("BIP0340/aux", aux_rand);
    let d_bytes = big_to_bytes32(&d);
    let t: [u8; 32] = d_bytes
        .iter()
        .zip(aux_hash.iter())
        .map(|(a, b)| a ^ b)
        .collect::<Vec<u8>>()
        .try_into()
        .ok()?;

    // k₀ = int(tagged_hash("BIP0340/nonce", t || P.x || msg)) mod n
    let nonce_input: Vec<u8> = t.iter().chain(p_x.iter()).chain(msg.iter()).copied().collect();
    let rand = tagged_hash("BIP0340/nonce", &nonce_input);
    let k0 = BigUint::from_bytes_be(&rand) % n;
    if k0.is_zero() {
        return None;
    }

    let r_point = match scalar_mul(&k0, &params.g, params) {
        CurvePoint::Finite(p) => p,
        CurvePoint::Infinity => return None,
    };

    // Negate k if R.y is odd
    let k = if has_even_y(&r_point) {
        k0.clone()
    } else {
        (n - &k0) % n
    };
    let r_x = big_to_bytes32(&r_point.x);

    // e = int(tagged_hash("BIP0340/challenge", R.x || P.x || msg)) mod n
    let challenge_input: Vec<u8> = r_x.iter().chain(p_x.iter()).chain(msg.iter()).copied().collect();
    let e_hash = tagged_hash("BIP0340/challenge", &challenge_input);
    let e = BigUint::from_bytes_be(&e_hash) % n;

    // s = (k + e·d) mod n  — linear, unlike ECDSA's k⁻¹(z + r·d)
    let s = (&k + &e * &d) % n;

    let steps = build_steps(&d0, &d, &p_point, &k0, &k, &r_point, &e, &s);
    let sig = SchnorrSignature { r: BigUint::from_bytes_be(&r_x), s };
    Some((sig, steps))
}

#[allow(clippy::too_many_arguments)]
fn build_steps(
    d0: &BigUint,
    d: &BigUint,
    p_point: &AffinePoint,
    k0: &BigUint,
    k: &BigUint,
    r_point: &AffinePoint,
    e: &BigUint,
    s: &BigUint,
) -> Vec<SchnorrStep> {
    let negated_d = d0 != d;
    let negated_k = k0 != k;

    vec![
        SchnorrStep {
            step_number: 1,
            title: "Public Key P = d\u{00b7}G (x-only)".to_string(),
            description: format!(
                "Compute P = d\u{00b7}G. BIP-340 public keys are the 32-byte x-coordinate only \
                 (even-y convention). {}",
                if negated_d {
                    "P.y is odd \u{2014} d negated to d = n\u{2212}d₀ so that P has even y."
                } else {
                    "P.y is even \u{2014} d unchanged."
                }
            ),
            formula: "P = d\u{00b7}G; pubkey = P.x (32 bytes)".to_string(),
            result: format!("P.x = {}", fmt_hex64(&p_point.x)),
        },
        SchnorrStep {
            step_number: 2,
            title: "Nonce k\u{2080} from BIP-340/aux + BIP-340/nonce".to_string(),
            description: "k\u{2080} = int(H\u{209f}\u{2092}\u{209c}\u{2090}\u{2094}(t \u{2016} P.x \u{2016} msg)) mod n, \
                where t = d XOR H\u{2090}\u{2091}\u{2093}(aux_rand). \
                The XOR with aux_rand lets signers inject fresh entropy while \
                the nonce remains fully deterministic if aux_rand is fixed \u{2014} \
                unlike RFC 6979, which is HMAC-based.".to_string(),
            formula: "k\u{2080} = H_nonce(t \u{2016} P.x \u{2016} msg) mod n".to_string(),
            result: format!("k\u{2080} = {}", fmt_hex64(k0)),
        },
        SchnorrStep {
            step_number: 3,
            title: "Nonce Point R = k\u{2080}\u{00b7}G (even-y)".to_string(),
            description: format!(
                "Compute R = k\u{2080}\u{00b7}G. R.x uniquely determines R once the parity is fixed \
                 by convention to even-y. {}",
                if negated_k {
                    "R.y is odd \u{2014} k negated to k = n\u{2212}k\u{2080}."
                } else {
                    "R.y is even \u{2014} k\u{2080} unchanged."
                }
            ),
            formula: "R = k\u{2080}\u{00b7}G; sig.r = R.x".to_string(),
            result: format!("R.x = {}", fmt_hex64(&r_point.x)),
        },
        SchnorrStep {
            step_number: 4,
            title: "Challenge e = H_challenge(R.x \u{2016} P.x \u{2016} msg)".to_string(),
            description: "e = int(tagged_hash(\"BIP0340/challenge\", R.x \u{2016} P.x \u{2016} msg)) mod n. \
                Binding e to (R, P, msg) means any change to the message or key produces \
                a completely different e, making forgery equivalent to breaking SHA-256 \
                or solving ECDLP.".to_string(),
            formula: "e = H_challenge(R.x \u{2016} P.x \u{2016} msg) mod n".to_string(),
            result: format!("e = {}", fmt_hex64(e)),
        },
        SchnorrStep {
            step_number: 5,
            title: "Signature s = k + e\u{00b7}d (mod n)".to_string(),
            description: "s = (k + e\u{00b7}d) mod n. \
                Unlike ECDSA\u{2019}s s = k\u{207b}\u{00b9}(z + r\u{00b7}d), \
                Schnorr\u{2019}s equation is linear in the nonce. \
                This linearity is what makes native key aggregation (MuSig2) \
                and batch verification possible \u{2014} multiple (R\u{1d62}, s\u{1d62}) pairs \
                can be combined into one equation.".to_string(),
            formula: "s = (k + e\u{00b7}d) mod n".to_string(),
            result: format!("s = {}", fmt_hex64(s)),
        },
    ]
}

pub fn verify(
    pubkey_x_bytes: &[u8; 32],
    r_bytes: &[u8; 32],
    s_bytes: &[u8; 32],
    msg: &[u8; 32],
    params: &CurveParams,
) -> bool {
    let n = &params.n;
    let px = BigUint::from_bytes_be(pubkey_x_bytes);
    let r = BigUint::from_bytes_be(r_bytes);
    let s = BigUint::from_bytes_be(s_bytes);

    if px >= params.p || r >= params.p || s >= *n {
        return false;
    }

    let p_point = match lift_x(&px, params) {
        Some(p) => p,
        None => return false,
    };

    let challenge_input: Vec<u8> = r_bytes.iter().chain(pubkey_x_bytes.iter()).chain(msg.iter()).copied().collect();
    let e = BigUint::from_bytes_be(&tagged_hash("BIP0340/challenge", &challenge_input)) % n;

    // R' = s·G + (n−e)·P  (equivalent to s·G − e·P without needing point negation)
    let neg_e = (n - &e) % n;
    let sg = scalar_mul(&s, &params.g, params);
    let ep = scalar_mul(&neg_e, &p_point, params);
    let r_prime = point_add(&sg, &ep, params);

    match r_prime {
        CurvePoint::Infinity => false,
        CurvePoint::Finite(rp) => has_even_y(&rp) && rp.x == r,
    }
}
