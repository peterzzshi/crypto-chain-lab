/// Multiply two bytes in GF(2⁸) with irreducible polynomial x⁸+x⁴+x³+x+1 (0x11b).
pub fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            result ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    result
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn state_to_row_strings(state: &[[u8; 4]; 4]) -> Vec<String> {
    (0..4).map(|row| {
        (0..4).map(|col| format!("{:02x}", state[row][col])).collect::<Vec<_>>().join(" ")
    }).collect()
}
