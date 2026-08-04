use super::constants::ROUND_CONSTANTS;
use super::math_utils::{ch, gamma0, gamma1, maj, sigma0, sigma1};
use super::types::{Block, Hash};

pub fn compress_block(hash: Hash, block: &Block, show_steps: bool) -> Hash {
    // Prepare message schedule
    let mut w = [0u32; 64];

    // Copy block into first 16 words
    w[0..16].copy_from_slice(block);

    // Extend the first 16 words into the remaining 48 words
    for t in 16..64 {
        w[t] = gamma1(w[t - 2])
            .wrapping_add(w[t - 7])
            .wrapping_add(gamma0(w[t - 15]))
            .wrapping_add(w[t - 16]);
    }

    if show_steps {
        println!("\n  Message Schedule (W[0] to W[63]):");
        for (i, word) in w.iter().enumerate() {
            if i < 16 {
                println!("    W[{:2}] = 0x{:08x} (from block)", i, word);
            } else {
                println!("    W[{:2}] = 0x{:08x} (computed)", i, word);
            }
        }
    }

    // Initialize working variables
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = hash;

    if show_steps {
        println!("\n  Initial working variables:");
        println!("    a = 0x{:08x}, b = 0x{:08x}, c = 0x{:08x}, d = 0x{:08x}", a, b, c, d);
        println!("    e = 0x{:08x}, f = 0x{:08x}, g = 0x{:08x}, h = 0x{:08x}", e, f, g, h);
    }

    // Main loop (64 rounds)
    for t in 0..64 {
        let t1 = h
            .wrapping_add(sigma1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(ROUND_CONSTANTS[t])
            .wrapping_add(w[t]);

        let t2 = sigma0(a).wrapping_add(maj(a, b, c));

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);

        if show_steps && (!(8..56).contains(&t) || t % 8 == 7) {
            println!("\n  Round {}:", t + 1);
            println!("    T1 = h + Σ₁(e) + Ch(e,f,g) + K[{}] + W[{}]", t, t);
            println!(
                "       = 0x{:08x} + Σ₁(0x{:08x}) + Ch(0x{:08x},0x{:08x},0x{:08x}) + 0x{:08x} + 0x{:08x}",
                hash[7 - (t % 8)],
                e,
                e,
                f,
                g,
                ROUND_CONSTANTS[t],
                w[t]
            );
            println!("       = 0x{:08x}", t1);
            println!("    T2 = Σ₀(a) + Maj(a,b,c) = 0x{:08x}", t2);
            println!("    New values: a=0x{:08x}, e=0x{:08x}", a, e);
        }
    }

    // Add compressed chunk to current hash value
    let result = [
        hash[0].wrapping_add(a),
        hash[1].wrapping_add(b),
        hash[2].wrapping_add(c),
        hash[3].wrapping_add(d),
        hash[4].wrapping_add(e),
        hash[5].wrapping_add(f),
        hash[6].wrapping_add(g),
        hash[7].wrapping_add(h),
    ];

    if show_steps {
        println!("\n  Final addition:");
        for i in 0..8 {
            println!(
                "    H[{}] = 0x{:08x} + 0x{:08x} = 0x{:08x}",
                i,
                hash[i],
                [a, b, c, d, e, f, g, h][i],
                result[i]
            );
        }
    }

    result
}
