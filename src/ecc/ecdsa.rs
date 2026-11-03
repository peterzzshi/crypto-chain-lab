use num_bigint::BigUint;
use num_traits::Zero;
use sha2::{Digest, Sha256};

use super::math_utils::{point_add, scalar_mul};
use super::types::{CurveParams, CurvePoint, EcdsaSignature};

fn big_to_bytes32(n: &BigUint) -> [u8; 32] {
    let b = n.to_bytes_be();
    debug_assert!(b.len() <= 32, "value exceeds 256 bits");
    let mut out = [0u8; 32];
    let len = b.len().min(32);
    out[32 - len..].copy_from_slice(&b[b.len() - len..]);
    out
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut padded = [0u8; BLOCK];
    if key.len() > BLOCK {
        let h: [u8; 32] = Sha256::digest(key).into();
        padded[..32].copy_from_slice(&h);
    } else {
        padded[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= padded[i];
        opad[i] ^= padded[i];
    }
    let inner: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(ipad);
        h.update(data);
        h.finalize().into()
    };
    let mut h = Sha256::new();
    h.update(opad);
    h.update(inner);
    h.finalize().into()
}

// RFC 6979 §2.4 — deterministic k for secp256k1 (qlen = 256 bits = 32 bytes)
fn rfc6979_k(privkey: &BigUint, msg_hash: &[u8], n: &BigUint) -> BigUint {
    let x = big_to_bytes32(privkey);
    let h1 = big_to_bytes32(&(BigUint::from_bytes_be(msg_hash) % n));

    let mut v = [0x01u8; 32];
    let mut k = [0x00u8; 32];

    let mut buf: Vec<u8> = Vec::with_capacity(97);
    buf.extend_from_slice(&v);
    buf.push(0x00);
    buf.extend_from_slice(&x);
    buf.extend_from_slice(&h1);
    k = hmac_sha256(&k, &buf);
    v = hmac_sha256(&k, &v);

    buf.clear();
    buf.extend_from_slice(&v);
    buf.push(0x01);
    buf.extend_from_slice(&x);
    buf.extend_from_slice(&h1);
    k = hmac_sha256(&k, &buf);
    v = hmac_sha256(&k, &v);

    loop {
        v = hmac_sha256(&k, &v);
        let candidate = BigUint::from_bytes_be(&v) % n;
        if !candidate.is_zero() {
            return candidate;
        }
        let retry: Vec<u8> = v.iter().copied().chain([0x00]).collect();
        k = hmac_sha256(&k, &retry);
        v = hmac_sha256(&k, &v);
    }
}

// Fermat's little theorem: a^(n-2) mod n — only correct when n is prime.
// For ECDSA this is always the secp256k1 group order, which is prime.
fn inv_mod_n(a: &BigUint, n: &BigUint) -> Option<BigUint> {
    if a.is_zero() {
        return None;
    }
    Some(a.modpow(&(n - BigUint::from(2u32)), n))
}

pub fn sign(msg_hash: &[u8], private_key: &BigUint, params: &CurveParams) -> Option<EcdsaSignature> {
    let n = &params.n;
    let k = rfc6979_k(private_key, msg_hash, n);
    let r = match scalar_mul(&k, &params.g, params) {
        CurvePoint::Finite(p) => &p.x % n,
        CurvePoint::Infinity => return None,
    };
    if r.is_zero() {
        return None;
    }
    let z = BigUint::from_bytes_be(msg_hash) % n;
    let k_inv = inv_mod_n(&k, n)?;
    let s = (&k_inv * (z + &r * private_key)) % n;
    if s.is_zero() {
        return None;
    }
    Some(EcdsaSignature { r, s })
}

pub fn verify(
    msg_hash: &[u8],
    sig: &EcdsaSignature,
    public_key: &CurvePoint,
    params: &CurveParams,
) -> bool {
    let n = &params.n;
    if sig.r.is_zero() || sig.r >= *n || sig.s.is_zero() || sig.s >= *n {
        return false;
    }
    let pub_pt = match public_key {
        CurvePoint::Finite(p) => p,
        CurvePoint::Infinity => return false,
    };
    let z = BigUint::from_bytes_be(msg_hash) % n;
    let s_inv = match inv_mod_n(&sig.s, n) {
        Some(v) => v,
        None => return false,
    };
    let u1 = (&z * &s_inv) % n;
    let u2 = (&sig.r * &s_inv) % n;
    let result = point_add(
        &scalar_mul(&u1, &params.g, params),
        &scalar_mul(&u2, pub_pt, params),
        params,
    );
    match result {
        CurvePoint::Finite(p) => (&p.x % n) == sig.r,
        CurvePoint::Infinity => false,
    }
}
