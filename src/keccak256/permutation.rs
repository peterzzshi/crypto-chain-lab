use super::constants::{ROUND_CONSTANTS, RHO_OFFSETS};
use super::types::State;

fn theta(state: &mut State) {
    let mut c = [0u64; 5];
    for x in 0..5 {
        c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    let mut d = [0u64; 5];
    for x in 0..5 {
        d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
    }
    for lane in 0..25 {
        state[lane] ^= d[lane % 5];
    }
}

fn rho_pi(state: &State) -> State {
    let mut result = [0u64; 25];
    for x in 0..5usize {
        for y in 0..5usize {
            // π: new[x][y] = old[(x+3y)%5][x] with ρ rotation applied to the source
            let src = (x + 3 * y) % 5 + 5 * x;
            result[x + 5 * y] = state[src].rotate_left(RHO_OFFSETS[src]);
        }
    }
    result
}

fn chi(state: &State) -> State {
    let mut result = [0u64; 25];
    for y in 0..5 {
        for x in 0..5 {
            result[x + 5 * y] =
                state[x + 5 * y] ^ ((!state[(x + 1) % 5 + 5 * y]) & state[(x + 2) % 5 + 5 * y]);
        }
    }
    result
}

pub fn keccak_f1600(state: &mut State) {
    for &rc in &ROUND_CONSTANTS {
        theta(state);
        *state = rho_pi(state);
        *state = chi(state);
        state[0] ^= rc;
    }
}

// Run the permutation and capture state snapshots after every 6 rounds.
// Returns (final_state, snapshots) where snapshots[i] is after rounds (i*6+1)..(i*6+6).
pub fn keccak_f1600_with_steps(state: &mut State) -> Vec<State> {
    let mut snapshots = Vec::with_capacity(4);
    for (r, &rc) in ROUND_CONSTANTS.iter().enumerate() {
        theta(state);
        *state = rho_pi(state);
        *state = chi(state);
        state[0] ^= rc;
        if r == 5 || r == 11 || r == 17 || r == 23 {
            snapshots.push(*state);
        }
    }
    snapshots
}
