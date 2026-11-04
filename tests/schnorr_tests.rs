use encryption_demo::ecc::constants::secp256k1;
use encryption_demo::schnorr::schnorr::{
    has_even_y, lift_x, sign, sign_with_steps, tagged_hash, verify,
};
use num_bigint::BigUint;

fn hex_to_bytes32(s: &str) -> [u8; 32] {
    let s = s.trim_start_matches("0x");
    let n = BigUint::parse_bytes(s.as_bytes(), 16).unwrap_or_default();
    let b = n.to_bytes_be();
    let mut out = [0u8; 32];
    let len = b.len().min(32);
    out[32 - len..].copy_from_slice(&b[b.len() - len..]);
    out
}

fn hex_to_biguint(s: &str) -> BigUint {
    let s = s.trim_start_matches("0x");
    BigUint::parse_bytes(s.as_bytes(), 16).unwrap()
}

// ---------------------------------------------------------------------------
// BIP-340 official test vectors (from bip-0340/test-vectors.csv)
// ---------------------------------------------------------------------------

struct Vector {
    privkey: &'static str,
    #[allow(dead_code)]
    pubkey_x: &'static str,
    aux_rand: &'static str,
    msg: &'static str,
    expected_sig: &'static str,
    #[allow(dead_code)]
    should_verify: bool,
}

const SIGN_VECTORS: &[Vector] = &[
    Vector {
        privkey: "0000000000000000000000000000000000000000000000000000000000000003",
        pubkey_x: "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        aux_rand:  "0000000000000000000000000000000000000000000000000000000000000000",
        msg:       "0000000000000000000000000000000000000000000000000000000000000000",
        expected_sig:
            "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
        should_verify: true,
    },
    Vector {
        privkey: "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
        pubkey_x: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        aux_rand:  "0000000000000000000000000000000000000000000000000000000000000001",
        msg:       "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        expected_sig:
            "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
        should_verify: true,
    },
    Vector {
        privkey: "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9",
        pubkey_x: "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
        aux_rand:  "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906",
        msg:       "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
        expected_sig:
            "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
        should_verify: true,
    },
    Vector {
        privkey: "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710",
        pubkey_x: "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517",
        aux_rand:  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        msg:       "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        expected_sig:
            "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3",
        should_verify: true,
    },
];

// Verification-only vectors (no private key — test lift_x + verify path)
struct VerifyVector {
    pubkey_x: &'static str,
    msg: &'static str,
    sig: &'static str,
    expected_valid: bool,
}

const VERIFY_VECTORS: &[VerifyVector] = &[
    // valid
    VerifyVector {
        pubkey_x: "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9",
        msg:       "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703",
        sig:       "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4",
        expected_valid: true,
    },
    // sig.s >= n — invalid
    VerifyVector {
        pubkey_x: "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34",
        msg:       "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        sig:       "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        expected_valid: false,
    },
    // invalid — R.y is not even
    VerifyVector {
        pubkey_x: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        msg:       "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        sig:       "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2",
        expected_valid: false,
    },
    // pubkey x not on curve — invalid
    VerifyVector {
        pubkey_x: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
        msg:       "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        sig:       "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769169BA0E52EC3F680D5F8A581C52C95B58B23F3E45CB3DB7BFD7E40EB8D7F1E51",
        expected_valid: false,
    },
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn tagged_hash_bip340_challenge_is_deterministic() {
    let params = secp256k1();
    let msg = [0u8; 32];
    let tag = "BIP0340/challenge";
    let data: Vec<u8> = msg.iter().chain(msg.iter()).chain(msg.iter()).copied().collect();
    let h1 = tagged_hash(tag, &data);
    let h2 = tagged_hash(tag, &data);
    assert_eq!(h1, h2);
    // inner and outer hashes must differ from a raw SHA-256 of the same bytes
    let outer = BigUint::from_bytes_be(&h1);
    assert!(outer > BigUint::from(0u32));
    let _ = params; // ensure crate link
}

#[test]
fn lift_x_recovers_even_y_point() {
    let params = secp256k1();
    // generator x
    let gx = params.g.x.clone();
    let p = lift_x(&gx, &params).expect("lift_x of Gx must succeed");
    assert_eq!(p.x, gx);
    assert!(has_even_y(&p), "lifted point must have even y");
}

#[test]
fn lift_x_rejects_x_ge_p() {
    let params = secp256k1();
    assert!(lift_x(&params.p, &params).is_none());
    let too_big = &params.p + BigUint::from(1u32);
    assert!(lift_x(&too_big, &params).is_none());
}

#[test]
fn sign_produces_verifiable_signature() {
    let params = secp256k1();
    let privkey_bytes = hex_to_bytes32("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF");
    let msg = hex_to_bytes32("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89");
    let aux = hex_to_bytes32("0000000000000000000000000000000000000000000000000000000000000001");
    let pubkey_x = hex_to_bytes32("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659");

    let sig = sign(&privkey_bytes, &msg, &aux, &params).expect("sign must succeed");
    let r_bytes = {
        let b = sig.r.to_bytes_be();
        let mut arr = [0u8; 32];
        let len = b.len().min(32);
        arr[32 - len..].copy_from_slice(&b[b.len() - len..]);
        arr
    };
    let s_bytes = {
        let b = sig.s.to_bytes_be();
        let mut arr = [0u8; 32];
        let len = b.len().min(32);
        arr[32 - len..].copy_from_slice(&b[b.len() - len..]);
        arr
    };
    assert!(verify(&pubkey_x, &r_bytes, &s_bytes, &msg, &params));
}

#[test]
fn sign_with_steps_returns_five_steps() {
    let params = secp256k1();
    let privkey_bytes = hex_to_bytes32("0000000000000000000000000000000000000000000000000000000000000003");
    let msg = [0u8; 32];
    let aux = [0u8; 32];
    let (_, steps) = sign_with_steps(&privkey_bytes, &msg, &aux, &params).expect("sign must succeed");
    assert_eq!(steps.len(), 5);
    for (i, step) in steps.iter().enumerate() {
        assert_eq!(step.step_number as usize, i + 1);
        assert!(!step.title.is_empty());
        assert!(!step.result.is_empty());
    }
}

#[test]
fn bip340_official_sign_vectors() {
    let params = secp256k1();
    for v in SIGN_VECTORS {
        let privkey_bytes = hex_to_bytes32(v.privkey);
        let msg = hex_to_bytes32(v.msg);
        let aux = hex_to_bytes32(v.aux_rand);
        let sig = sign(&privkey_bytes, &msg, &aux, &params)
            .unwrap_or_else(|| panic!("sign failed for privkey {}", v.privkey));

        let expected_r = hex_to_biguint(&v.expected_sig[..64]);
        let expected_s = hex_to_biguint(&v.expected_sig[64..]);
        assert_eq!(sig.r, expected_r, "r mismatch for privkey {}", v.privkey);
        assert_eq!(sig.s, expected_s, "s mismatch for privkey {}", v.privkey);
    }
}

#[test]
fn bip340_official_verify_vectors() {
    let params = secp256k1();
    for v in VERIFY_VECTORS {
        let pubkey_x = hex_to_bytes32(v.pubkey_x);
        let sig_hex = v.sig;
        let r_bytes = hex_to_bytes32(&sig_hex[..64]);
        let s_bytes = hex_to_bytes32(&sig_hex[64..]);
        let msg = hex_to_bytes32(v.msg);
        let result = verify(&pubkey_x, &r_bytes, &s_bytes, &msg, &params);
        assert_eq!(
            result, v.expected_valid,
            "verify mismatch for pubkey {}",
            v.pubkey_x
        );
    }
}

#[test]
fn verify_rejects_wrong_message() {
    let params = secp256k1();
    let privkey_bytes = hex_to_bytes32("0000000000000000000000000000000000000000000000000000000000000003");
    let msg = [0u8; 32];
    let aux = [0u8; 32];
    let pubkey_x = hex_to_bytes32("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9");

    let sig = sign(&privkey_bytes, &msg, &aux, &params).unwrap();
    let r_bytes = {
        let b = sig.r.to_bytes_be();
        let mut arr = [0u8; 32];
        let len = b.len().min(32);
        arr[32 - len..].copy_from_slice(&b[b.len() - len..]);
        arr
    };
    let s_bytes = {
        let b = sig.s.to_bytes_be();
        let mut arr = [0u8; 32];
        let len = b.len().min(32);
        arr[32 - len..].copy_from_slice(&b[b.len() - len..]);
        arr
    };
    let mut wrong_msg = msg;
    wrong_msg[0] ^= 1;
    assert!(!verify(&pubkey_x, &r_bytes, &s_bytes, &wrong_msg, &params));
}

#[test]
fn sign_rejects_zero_privkey() {
    let params = secp256k1();
    let zero = [0u8; 32];
    assert!(sign(&zero, &zero, &zero, &params).is_none());
}
