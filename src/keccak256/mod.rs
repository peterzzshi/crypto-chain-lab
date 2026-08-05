pub mod constants;
pub mod permutation;
pub mod types;

use permutation::{keccak_f1600, keccak_f1600_with_steps};
use types::State;

pub const RATE: usize = 136; // bytes; capacity = 64 bytes

fn pad(message: &[u8]) -> Vec<u8> {
    let mut padded = message.to_vec();
    // Keccak-256 (original, not NIST SHA3): domain separation byte 0x01
    padded.push(0x01);
    while padded.len() % RATE != 0 {
        padded.push(0x00);
    }
    *padded.last_mut().unwrap() |= 0x80;
    padded
}

fn absorb(state: &mut State, block: &[u8]) {
    for i in 0..(RATE / 8) {
        state[i] ^= u64::from_le_bytes(block[i * 8..i * 8 + 8].try_into().unwrap());
    }
}

fn squeeze(state: &State) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..i * 8 + 8].copy_from_slice(&state[i].to_le_bytes());
    }
    out
}

fn fmt_state_lanes(state: &State) -> Vec<String> {
    state
        .iter()
        .enumerate()
        .map(|(i, lane)| format!("A[{},{}] = {:016x}", i % 5, i / 5, lane))
        .collect()
}

pub fn keccak256(message: &[u8]) -> [u8; 32] {
    let padded = pad(message);
    let mut state: State = [0u64; 25];
    for block in padded.chunks(RATE) {
        absorb(&mut state, block);
        keccak_f1600(&mut state);
    }
    squeeze(&state)
}

pub struct Keccak256Step {
    pub step_number: u32,
    pub title: String,
    pub description: String,
    pub data: Vec<String>,
}

pub fn keccak256_with_steps(message: &[u8]) -> ([u8; 32], Vec<Keccak256Step>) {
    let mut steps: Vec<Keccak256Step> = Vec::new();
    let padded = pad(message);

    let step_num = &mut 1u32;
    let next = |n: &mut u32| { let v = *n; *n += 1; v };

    // Step: input + padding
    let pad_hex: Vec<String> = padded
        .iter()
        .enumerate()
        .map(|(i, b)| {
            if i < message.len() {
                format!("{:02x}", b)
            } else if *b == 0x01 {
                "01↑".to_string()
            } else if *b == 0x80 || *b == 0x81 {
                format!("{:02x}↑", b)
            } else {
                "00".to_string()
            }
        })
        .collect();

    steps.push(Keccak256Step {
        step_number: next(step_num),
        title: "Message Padding (Keccak multi-rate)".to_string(),
        description: format!(
            "Append 0x01 (Keccak domain suffix), pad with 0x00, XOR 0x80 into last byte. Rate = {} bytes ({} bits), capacity = {} bytes ({} bits). {} message byte(s) → {} padded byte(s) in {} block(s).",
            RATE, RATE * 8, 200 - RATE, (200 - RATE) * 8,
            message.len(), padded.len(), padded.len() / RATE
        ),
        data: vec![
            format!("Input ({} bytes): {:02x?}", message.len(), message),
            format!("Padded ({} bytes) [01↑=padding start, 80↑=padding end]:", padded.len()),
            pad_hex.chunks(17).map(|c| c.join(" ")).collect::<Vec<_>>().join("\n"),
        ],
    });

    // Step: initial state
    steps.push(Keccak256Step {
        step_number: next(step_num),
        title: "Initial State S₀ (5×5 zero matrix)".to_string(),
        description: "The Keccak sponge state is a 5×5 array of 64-bit lanes (1600 bits total). All lanes start at zero. Rate portion (first 17 lanes = 1088 bits) is XOR-mixed with the padded message; capacity portion (last 8 lanes = 512 bits) is never directly touched by input — this is the security margin.".to_string(),
        data: vec!["All 25 lanes = 0x0000000000000000".to_string()],
    });

    let mut state: State = [0u64; 25];
    let mut block_num = 0usize;

    for block in padded.chunks(RATE) {
        block_num += 1;

        // Show state after absorb (XOR) but before permutation
        absorb(&mut state, block);
        let absorbed_data = fmt_state_lanes(&state);

        steps.push(Keccak256Step {
            step_number: next(step_num),
            title: format!("Absorb Block {} — XOR message into rate lanes", block_num),
            description: format!(
                "XOR the {} rate bytes of block {} into the first {} lanes of the state (A[0,0]..A[1,2]). Capacity lanes A[2,2]..A[4,4] are untouched.",
                RATE, block_num, RATE / 8
            ),
            data: absorbed_data,
        });

        // Permutation with round snapshots
        let snapshots = keccak_f1600_with_steps(&mut state);

        let group_labels = [
            ("Rounds 1–6", "θ→ρπ→χ→ι applied 6 times. θ diffuses each lane across its column; ρπ rotates and rearranges lanes; χ applies the only non-linear step; ι breaks symmetry with a round constant."),
            ("Rounds 7–12", "Second group of 6 rounds. Avalanche effect is already strong — flipping one input bit will have changed roughly half of all 1600 state bits by now."),
            ("Rounds 13–18", "Third group. The full 24-round count is chosen conservatively: the best known attacks require ≥ 6 rounds to find any structural distinguisher."),
            ("Rounds 19–24", "Final 6 rounds complete the Keccak-f[1600] permutation. The first 256 bits of the resulting state are the hash output."),
        ];

        for (i, snap) in snapshots.iter().enumerate() {
            steps.push(Keccak256Step {
                step_number: next(step_num),
                title: format!("Keccak-f[1600]: {}", group_labels[i].0),
                description: group_labels[i].1.to_string(),
                data: fmt_state_lanes(snap),
            });
        }
    }

    let hash_bytes = squeeze(&state);
    let hash_hex = hex::encode(hash_bytes);

    steps.push(Keccak256Step {
        step_number: next(step_num),
        title: "Squeeze — Extract 256-bit Digest".to_string(),
        description: "Read the first 256 bits (32 bytes = 4 lanes) from the state in little-endian byte order. The result is the Keccak-256 hash — used as Ethereum's native hash in address derivation, the EVM keccak256() opcode, EIP-712 typed-data signing, and Solidity's keccak256().".to_string(),
        data: vec![
            format!("Lane A[0,0]: {:016x}", state[0]),
            format!("Lane A[1,0]: {:016x}", state[1]),
            format!("Lane A[2,0]: {:016x}", state[2]),
            format!("Lane A[3,0]: {:016x}", state[3]),
            format!("Hash (256 bits): {}", hash_hex),
        ],
    });

    (hash_bytes, steps)
}
