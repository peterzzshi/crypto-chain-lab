use super::constants::{RCON, SBOX};
use super::types::Word;

fn sub_word(w: Word) -> Word {
    [SBOX[w[0] as usize], SBOX[w[1] as usize], SBOX[w[2] as usize], SBOX[w[3] as usize]]
}

fn rot_word(w: Word) -> Word {
    [w[1], w[2], w[3], w[0]]
}

fn xor_words(a: Word, b: Word) -> Word {
    [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]]
}

/// Expand a 16-byte key into 44 words (11 round keys × 4 words each).
pub fn expand_key(key: &[u8; 16]) -> Vec<Word> {
    let mut w: Vec<Word> = (0..4)
        .map(|i| [key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]])
        .collect();

    for i in 4..44 {
        let mut temp = w[i - 1];
        if i % 4 == 0 {
            temp = xor_words(sub_word(rot_word(temp)), [RCON[i / 4], 0, 0, 0]);
        }
        w.push(xor_words(w[i - 4], temp));
    }
    w
}

/// Extract the round key matrix for round r from the expanded key schedule.
/// round_key[row][col] = w[4r + col][row]
pub fn round_key(schedule: &[Word], round: usize) -> [[u8; 4]; 4] {
    let mut rk = [[0u8; 4]; 4];
    for col in 0..4 {
        for row in 0..4 {
            rk[row][col] = schedule[4 * round + col][row];
        }
    }
    rk
}
