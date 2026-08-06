use super::cipher::{
    add_round_key, bytes_to_state, decrypt_block, mix_columns, shift_rows,
    state_to_bytes, sub_bytes,
};
use super::key_schedule::{expand_key, round_key};
use super::math_utils::{bytes_to_hex, state_to_row_strings};
use super::types::{Aes128DemoResult, Aes128Step};

pub fn run_aes128_demo(plaintext: &[u8; 16], key: &[u8; 16]) -> Aes128DemoResult {
    let mut steps: Vec<Aes128Step> = Vec::new();
    let schedule = expand_key(key);

    steps.push(Aes128Step {
        step_number: 1,
        title: "Key Schedule".to_string(),
        description:
            "Expand 128-bit key into 11 round keys (44 words). Each word W[i] = W[i-4] XOR f(W[i-1]); f applies RotWord+SubWord+Rcon every 4th word."
                .to_string(),
        state_hex: (0..11)
            .map(|r| {
                let rk = round_key(&schedule, r);
                format!("RK[{}]: {}", r, state_to_row_strings(&rk).join(" | "))
            })
            .collect(),
    });

    let mut state = bytes_to_state(plaintext);
    let rk0 = round_key(&schedule, 0);

    steps.push(Aes128Step {
        step_number: 2,
        title: "Initial AddRoundKey (Round 0)".to_string(),
        description: "XOR plaintext with round key 0 before any substitutions.".to_string(),
        state_hex: {
            let pt_rows = state_to_row_strings(&state);
            let rk_rows = state_to_row_strings(&rk0);
            state = add_round_key(&state, &rk0);
            let out_rows = state_to_row_strings(&state);
            pt_rows
                .into_iter()
                .zip(rk_rows)
                .zip(out_rows)
                .map(|((pt, rk), out)| format!("{} XOR {} = {}", pt, rk, out))
                .collect()
        },
    });

    for round in 1u32..=10 {
        let after_sub = sub_bytes(&state);
        let after_shift = shift_rows(&after_sub);
        let after_mix = if round < 10 {
            mix_columns(&after_shift)
        } else {
            after_shift
        };
        let rk = round_key(&schedule, round as usize);
        let after_ark = add_round_key(&after_mix, &rk);

        steps.push(Aes128Step {
            step_number: 2 + round,
            title: format!(
                "Round {} ({})",
                round,
                if round == 10 {
                    "final \u{2014} no MixColumns"
                } else {
                    "full"
                }
            ),
            description: if round < 10 {
                "SubBytes \u{2192} ShiftRows \u{2192} MixColumns \u{2192} AddRoundKey".to_string()
            } else {
                "SubBytes \u{2192} ShiftRows \u{2192} AddRoundKey".to_string()
            },
            state_hex: {
                let mut lines = vec![
                    format!(
                        "After SubBytes:    {}",
                        state_to_row_strings(&after_sub).join(" | ")
                    ),
                    format!(
                        "After ShiftRows:   {}",
                        state_to_row_strings(&after_shift).join(" | ")
                    ),
                ];
                if round < 10 {
                    lines.push(format!(
                        "After MixColumns:  {}",
                        state_to_row_strings(&after_mix).join(" | ")
                    ));
                } else {
                    lines.push("MixColumns skipped in final round".to_string());
                }
                lines.push(format!(
                    "After AddRoundKey: {}",
                    state_to_row_strings(&after_ark).join(" | ")
                ));
                lines
            },
        });

        state = after_ark;
    }

    let ciphertext = state_to_bytes(&state);
    let decrypted = decrypt_block(&ciphertext, key);

    steps.push(Aes128Step {
        step_number: 13,
        title: "Decryption Verification".to_string(),
        description:
            "Apply inverse cipher to confirm decrypt(encrypt(p)) = p.".to_string(),
        state_hex: vec![
            format!("Ciphertext: {}", bytes_to_hex(&ciphertext)),
            format!("Decrypted:  {}", bytes_to_hex(&decrypted)),
            if decrypted == *plaintext {
                "\u{2713} Match \u{2014} cipher is correct".to_string()
            } else {
                "\u{2717} Mismatch".to_string()
            },
        ],
    });

    Aes128DemoResult {
        success: decrypted == *plaintext,
        error: None,
        plaintext_hex: bytes_to_hex(plaintext),
        key_hex: bytes_to_hex(key),
        ciphertext_hex: bytes_to_hex(&ciphertext),
        decrypted_hex: bytes_to_hex(&decrypted),
        steps,
    }
}
