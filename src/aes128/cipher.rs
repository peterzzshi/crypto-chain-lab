use super::constants::{INV_SBOX, SBOX};
use super::key_schedule::{expand_key, round_key};
use super::math_utils::gf_mul;
use super::types::State;

pub fn bytes_to_state(bytes: &[u8; 16]) -> State {
    let mut s = [[0u8; 4]; 4];
    for row in 0..4 {
        for col in 0..4 {
            s[row][col] = bytes[row + 4 * col];
        }
    }
    s
}

pub fn state_to_bytes(s: &State) -> [u8; 16] {
    let mut out = [0u8; 16];
    for row in 0..4 {
        for col in 0..4 {
            out[row + 4 * col] = s[row][col];
        }
    }
    out
}

pub fn add_round_key(s: &State, rk: &State) -> State {
    let mut out = [[0u8; 4]; 4];
    for row in 0..4 {
        for col in 0..4 {
            out[row][col] = s[row][col] ^ rk[row][col];
        }
    }
    out
}

pub fn sub_bytes(s: &State) -> State {
    let mut out = [[0u8; 4]; 4];
    for row in 0..4 {
        for col in 0..4 {
            out[row][col] = SBOX[s[row][col] as usize];
        }
    }
    out
}

pub fn inv_sub_bytes(s: &State) -> State {
    let mut out = [[0u8; 4]; 4];
    for row in 0..4 {
        for col in 0..4 {
            out[row][col] = INV_SBOX[s[row][col] as usize];
        }
    }
    out
}

pub fn shift_rows(s: &State) -> State {
    let mut out = [[0u8; 4]; 4];
    for row in 0..4 {
        for col in 0..4 {
            out[row][col] = s[row][(col + row) % 4];
        }
    }
    out
}

pub fn inv_shift_rows(s: &State) -> State {
    let mut out = [[0u8; 4]; 4];
    for row in 0..4 {
        for col in 0..4 {
            out[row][col] = s[row][(col + 4 - row) % 4];
        }
    }
    out
}

pub fn mix_columns(s: &State) -> State {
    let mut out = [[0u8; 4]; 4];
    for col in 0..4 {
        let (a, b, c, d) = (s[0][col], s[1][col], s[2][col], s[3][col]);
        out[0][col] = gf_mul(2,a) ^ gf_mul(3,b) ^ c ^ d;
        out[1][col] = a ^ gf_mul(2,b) ^ gf_mul(3,c) ^ d;
        out[2][col] = a ^ b ^ gf_mul(2,c) ^ gf_mul(3,d);
        out[3][col] = gf_mul(3,a) ^ b ^ c ^ gf_mul(2,d);
    }
    out
}

pub fn inv_mix_columns(s: &State) -> State {
    let mut out = [[0u8; 4]; 4];
    for col in 0..4 {
        let (a, b, c, d) = (s[0][col], s[1][col], s[2][col], s[3][col]);
        out[0][col] = gf_mul(0x0e,a) ^ gf_mul(0x0b,b) ^ gf_mul(0x0d,c) ^ gf_mul(0x09,d);
        out[1][col] = gf_mul(0x09,a) ^ gf_mul(0x0e,b) ^ gf_mul(0x0b,c) ^ gf_mul(0x0d,d);
        out[2][col] = gf_mul(0x0d,a) ^ gf_mul(0x09,b) ^ gf_mul(0x0e,c) ^ gf_mul(0x0b,d);
        out[3][col] = gf_mul(0x0b,a) ^ gf_mul(0x0d,b) ^ gf_mul(0x09,c) ^ gf_mul(0x0e,d);
    }
    out
}

pub fn encrypt_block(plaintext: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
    let schedule = expand_key(key);
    let mut state = bytes_to_state(plaintext);
    state = add_round_key(&state, &round_key(&schedule, 0));
    for round in 1..=10 {
        state = sub_bytes(&state);
        state = shift_rows(&state);
        if round < 10 {
            state = mix_columns(&state);
        }
        state = add_round_key(&state, &round_key(&schedule, round));
    }
    state_to_bytes(&state)
}

pub fn decrypt_block(ciphertext: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
    let schedule = expand_key(key);
    let mut state = bytes_to_state(ciphertext);
    state = add_round_key(&state, &round_key(&schedule, 10));
    for round in (0..10).rev() {
        state = inv_shift_rows(&state);
        state = inv_sub_bytes(&state);
        state = add_round_key(&state, &round_key(&schedule, round));
        if round > 0 {
            state = inv_mix_columns(&state);
        }
    }
    state_to_bytes(&state)
}
