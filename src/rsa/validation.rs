use super::math_utils::is_prime;
use num_bigint::BigUint;

pub(super) fn validate_primes(p: &BigUint, q: &BigUint) -> Result<(), String> {
    if !is_prime(p) || !is_prime(q) {
        return Err(format!("both p and q must be prime (got p={}, q={})", p, q));
    }
    if p == q {
        return Err(format!("p and q must be different (got p={}, q={})", p, q));
    }
    Ok(())
}

pub(super) fn is_valid_message_size(message: &BigUint, n: &BigUint) -> bool {
    message < n
}
