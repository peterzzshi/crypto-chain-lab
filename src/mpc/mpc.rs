use num_bigint::BigUint;
use num_traits::{One, Zero};
use sha2::{Digest, Sha256};

/// A Shamir share: (x, f(x)) over 𝔽_n where n is the secp256k1 group order.
pub struct Share {
    pub x: BigUint,
    pub y: BigUint,
}

/// Modular inverse via Fermat's little theorem: a^(n-2) mod n — valid when n is prime.
/// The secp256k1 group order n is prime, so this is correct for all Shamir ops over 𝔽_n.
fn field_inv(a: &BigUint, n: &BigUint) -> Option<BigUint> {
    if a.is_zero() {
        return None;
    }
    Some(a.modpow(&(n - BigUint::from(2u32)), n))
}

/// Split a secret `d` into `n_shares` with threshold `threshold` using a
/// degree-(threshold-1) polynomial f(x) = d + a₁x + a₂x² + … over 𝔽_n.
/// Coefficients are derived deterministically from SHA-256(d ‖ "mpc" ‖ i) so the
/// demo is reproducible without a randomness source.
pub fn split(secret: &BigUint, threshold: usize, n_shares: usize, n: &BigUint) -> Option<Vec<Share>> {
    if threshold == 0 || n_shares < threshold || threshold > 255 || n_shares > 255 {
        return None;
    }
    let s = secret % n;
    if s.is_zero() {
        return None;
    }

    // f(x) = s + a₁x + … + a_{t-1}x^{t-1}
    let mut coeffs: Vec<BigUint> = Vec::with_capacity(threshold);
    coeffs.push(s.clone());
    for i in 1..threshold {
        let mut h = Sha256::new();
        h.update(secret.to_bytes_be());
        h.update(b"mpc");
        h.update([i as u8]);
        let digest: [u8; 32] = h.finalize().into();
        coeffs.push(BigUint::from_bytes_be(&digest) % n);
    }

    let mut shares = Vec::with_capacity(n_shares);
    for x in 1..=n_shares {
        let xi = BigUint::from(x);
        // Horner's method: evaluate f(xi) mod n
        let mut acc = coeffs[threshold - 1].clone();
        for c in coeffs[..threshold - 1].iter().rev() {
            acc = ((&acc * &xi) % n + c) % n;
        }
        shares.push(Share { x: xi, y: acc });
    }
    Some(shares)
}

/// Reconstruct the secret from `threshold` shares via Lagrange interpolation at x = 0:
/// secret = Σ yᵢ · Lᵢ(0), where Lᵢ(0) = Π_{j≠i} (0 - xⱼ)/(xᵢ - xⱼ) mod n.
pub fn reconstruct(shares: &[Share], n: &BigUint) -> Option<BigUint> {
    if shares.is_empty() {
        return None;
    }
    let k = shares.len();

    let mut acc = BigUint::zero();
    for i in 0..k {
        let xi = &shares[i].x;
        let yi = &shares[i].y;

        let mut num = BigUint::one();
        let mut den = BigUint::one();
        for (j, share_j) in shares.iter().enumerate().take(k) {
            if i == j {
                continue;
            }
            let xj = &share_j.x;
            // (0 - xⱼ) mod n
            let neg_xj = (n - (xj % n)) % n;
            num = (&num * &neg_xj) % n;
            // (xᵢ - xⱼ) mod n
            let diff = if xi >= xj {
                (xi - xj) % n
            } else {
                (n - ((xj - xi) % n)) % n
            };
            den = (&den * &diff) % n;
        }
        let basis = (&num * field_inv(&den, n)?) % n;
        acc = (&acc + (yi * &basis) % n) % n;
    }
    Some(acc)
}
