use super::types::Word;

pub fn rotr(x: Word, n: u32) -> Word {
    x.rotate_right(n)
}

pub fn ch(x: Word, y: Word, z: Word) -> Word {
    (x & y) ^ (!x & z)
}

pub fn maj(x: Word, y: Word, z: Word) -> Word {
    (x & y) ^ (x & z) ^ (y & z)
}

pub fn sigma0(x: Word) -> Word {
    rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

pub fn sigma1(x: Word) -> Word {
    rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

pub fn gamma0(x: Word) -> Word {
    rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
}

pub fn gamma1(x: Word) -> Word {
    rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
}

pub fn bytes_to_words(bytes: &[u8]) -> Vec<Word> {
    bytes
        .chunks(4)
        .map(|chunk| {
            let mut word = 0u32;
            for (i, &byte) in chunk.iter().enumerate() {
                word |= (byte as u32) << (24 - 8 * i);
            }
            word
        })
        .collect()
}

pub fn words_to_hex(words: &[Word]) -> String {
    words
        .iter()
        .map(|word| format!("{:08x}", word))
        .collect::<Vec<_>>()
        .join("")
}
