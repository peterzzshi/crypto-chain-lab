use num_bigint::{BigInt, BigUint};
use num_traits::{One, ToPrimitive, Zero};

pub fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    if a.is_zero() || m.is_zero() {
        return None;
    }
    let mut old_r = BigInt::from(a.clone());
    let mut r = BigInt::from(m.clone());
    let mut old_s = BigInt::one();
    let mut s = BigInt::zero();

    while !r.is_zero() {
        let q = &old_r / &r;
        let (next_r, next_s) = (old_r - &q * &r, old_s - &q * &s);
        old_r = r;
        r = next_r;
        old_s = s;
        s = next_s;
    }

    if old_r != BigInt::one() {
        return None;
    }

    let m_int = BigInt::from(m.clone());
    let result = (old_s % &m_int + &m_int) % &m_int;
    result.to_biguint()
}

pub fn mod_pow(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    base.modpow(exp, modulus)
}

pub fn is_prime(n: &BigUint) -> bool {
    match n.to_u64() {
        Some(small) => is_prime_small(small),
        None => miller_rabin(n),
    }
}

fn is_prime_small(n: u64) -> bool {
    match n {
        0 | 1 => false,
        2 | 3 => true,
        n if n % 2 == 0 => false,
        n => {
            let limit = (n as f64).sqrt() as u64 + 1;
            (3..=limit).step_by(2).all(|d| n % d != 0)
        }
    }
}

fn miller_rabin(n: &BigUint) -> bool {
    let one = BigUint::one();
    let two = BigUint::from(2u32);

    if n < &two {
        return false;
    }
    if n == &two {
        return true;
    }
    if n % &two == BigUint::zero() {
        return false;
    }

    let n_minus_1 = n - &one;
    let mut r = 0u32;
    let mut d = n_minus_1.clone();
    while !d.bit(0) {
        r += 1;
        d >>= 1;
    }

    // Deterministic witnesses for n < 3,317,044,064,679,887,385,961,981
    let witnesses: &[u32] = &[2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];

    'outer: for &a in witnesses {
        let a_biguint = BigUint::from(a);
        if n == &a_biguint {
            return true;
        }
        if &a_biguint >= n {
            continue;
        }
        let mut x = a_biguint.modpow(&d, n);
        if x == one || x == n_minus_1 {
            continue;
        }
        for _ in 0..r.saturating_sub(1) {
            x = x.modpow(&two, n);
            if x == n_minus_1 {
                continue 'outer;
            }
        }
        return false;
    }
    true
}
