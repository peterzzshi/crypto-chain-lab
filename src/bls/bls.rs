// BLS12-381 signatures — minimal-pubkey-size variant
//   Private key : Scalar (32 bytes)
//   Public  key : G1 compressed (48 bytes)   pk = sk · G1
//   Signature   : G2 compressed (96 bytes)   sig = sk · H(m)
//   Verify      : e(pk, H(m)) == e(G1, sig)
//
// hash_to_g2 is a simplified hash-and-scalar approach suitable for an
// educational demo. It does not implement the IETF hash_to_curve spec.
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use ff::Field;
use sha2::{Digest, Sha256};

// --------------------------------------------------------------------------
// Internal helpers
// --------------------------------------------------------------------------

/// Hash msg to a G2 point deterministically via try-and-increment.
/// BLS12-381 r ≈ 0.73e×2^252 (top byte 0x73), so r < 2^255. Clearing the
/// MSB only bounds the candidate below 2^255 — still up to ~27% land at
/// ≥ r and are rejected by Scalar::from_bytes. Iterating with a counter
/// re-hashes until a canonical scalar appears. Sign and verify share this
/// function, so both derive the same H(m). Not the IETF hash_to_curve spec.
fn hash_to_g2(msg: &[u8]) -> G2Projective {
    let mut counter: u8 = 0u8;
    loop {
        let mut input: Vec<u8> = msg.to_vec();
        input.push(counter);
        let mut bytes: [u8; 32] = Sha256::digest(&input).into();
        bytes[31] &= 0x7f; // bound below 2^255
        bytes.reverse(); // SHA-256 is big-endian; from_bytes wants little-endian
        if let Some(scalar) = Option::<Scalar>::from(Scalar::from_bytes(&bytes)) {
            return G2Projective::generator() * scalar;
        }
        counter = counter.wrapping_add(1);
    }
}

fn scalar_from_be_bytes(b: &[u8; 32]) -> Option<Scalar> {
    let mut le = *b;
    le.reverse();
    Option::from(Scalar::from_bytes(&le))
}

pub fn pubkey_from_scalar(sk: &Scalar) -> G1Affine {
    G1Affine::from(G1Projective::generator() * sk)
}

// --------------------------------------------------------------------------
// Public API
// --------------------------------------------------------------------------

/// Returns (pk_compressed, sig_compressed) or None if privkey is invalid.
pub fn sign(privkey_bytes: &[u8; 32], msg: &[u8]) -> Option<([u8; 48], [u8; 96])> {
    let sk = scalar_from_be_bytes(privkey_bytes)?;
    if sk.is_zero().into() {
        return None;
    }
    let pk = G1Affine::from(G1Projective::generator() * sk);
    let h = hash_to_g2(msg);
    let sig = G2Affine::from(h * sk);
    Some((pk.to_compressed(), sig.to_compressed()))
}

/// Verify a single BLS signature.
pub fn verify(pubkey_bytes: &[u8; 48], sig_bytes: &[u8; 96], msg: &[u8]) -> bool {
    let pk = match Option::<G1Affine>::from(G1Affine::from_compressed(pubkey_bytes)) {
        Some(p) => p,
        None => return false,
    };
    let sig = match Option::<G2Affine>::from(G2Affine::from_compressed(sig_bytes)) {
        Some(s) => s,
        None => return false,
    };
    if bool::from(pk.is_identity()) || bool::from(sig.is_identity()) {
        return false;
    }
    let h = G2Affine::from(hash_to_g2(msg));
    // e(pk, H(m)) == e(G1, sig)
    pairing(&pk, &h) == pairing(&G1Affine::generator(), &sig)
}

/// Aggregate multiple G2 signatures into one.
pub fn aggregate_signatures(sig_bytes_list: &[[u8; 96]]) -> Option<[u8; 96]> {
    if sig_bytes_list.is_empty() {
        return None;
    }
    let mut agg = G2Projective::identity();
    for bytes in sig_bytes_list {
        let s = Option::<G2Affine>::from(G2Affine::from_compressed(bytes))?;
        if bool::from(s.is_identity()) {
            return None;
        }
        agg += G2Projective::from(s);
    }
    Some(G2Affine::from(agg).to_compressed())
}

/// Verify an aggregate signature over the same message from multiple pubkeys.
/// e(G1, agg_sig) == ∏ e(pkᵢ, H(m))
pub fn verify_aggregate(pubkey_bytes_list: &[[u8; 48]], msg: &[u8], agg_sig: &[u8; 96]) -> bool {
    if pubkey_bytes_list.is_empty() {
        return false;
    }
    let agg_sig_pt = match Option::<G2Affine>::from(G2Affine::from_compressed(agg_sig)) {
        Some(s) => s,
        None => return false,
    };
    if bool::from(agg_sig_pt.is_identity()) {
        return false;
    }
    let h = G2Affine::from(hash_to_g2(msg));

    // Combine pubkeys: agg_pk = ∑ pkᵢ (valid when all sign the same message)
    let mut agg_pk = G1Projective::identity();
    for bytes in pubkey_bytes_list {
        match Option::<G1Affine>::from(G1Affine::from_compressed(bytes)) {
            Some(pk) => {
                if bool::from(pk.is_identity()) {
                    return false;
                }
                agg_pk += G1Projective::from(pk);
            }
            None => return false,
        }
    }
    let agg_pk_affine = G1Affine::from(agg_pk);
    pairing(&agg_pk_affine, &h) == pairing(&G1Affine::generator(), &agg_sig_pt)
}
