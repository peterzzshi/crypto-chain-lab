# Architecture

Design decisions and tradeoffs for `crypto-chain-lab`.

---

## Module structure

Each algorithm is a self-contained module: `types`, `constants`, `math_utils`, core logic, `demo`
(CLI output), and `mod.rs` re-exporting the public surface. The `wasm/` module is a thin
translation layer that serialises Rust types to JSON for the TypeScript UI — it owns no business
logic.

```
src/
├── rsa/        RSA textbook implementation
├── sha256/     SHA-256 (FIPS 180-4)
├── keccak256/  Keccak-256 (Ethereum variant, domain byte 0x01)
├── ecc/        Short Weierstrass ECC — generic + secp256k1 + ECDSA
├── schnorr/    BIP-340 Schnorr signatures over secp256k1
├── bls/        BLS12-381 pairing-based signatures
├── mpc/        Shamir 2-of-3 threshold signing
├── aes128/     AES-128 block cipher (FIPS 197)
├── blockchain/ PoW chain built on the hashing primitives above
├── common/     Shared validation helpers
└── wasm/       wasm-bindgen exports — JSON serialisation only
```

The WASM boundary is always JSON: the TypeScript UI calls a `#[wasm_bindgen]` function, receives
a JSON string, and parses it. Rust state is never shared across the boundary.

---

## Algorithm choices and tradeoffs

### ECDSA over secp256k1

Deterministic nonce generation via RFC 6979 (HMAC-SHA256-based). The nonce `k` is derived from
the private key and message hash, so the same (key, message) pair always produces the same
signature — no entropy source needed, no nonce reuse risk in this educational context.

The implementation uses affine coordinates (x, y) as `BigUint` pairs. This is simpler to read but
slower than projective/Jacobian coordinates used in production libraries (where converting back to
affine requires a modular inverse on every point operation). For an educational demo over a 256-bit
scalar this is fine; for production use the `k256` crate.

Low-s canonicalisation (BIP-146) is not enforced. Production libraries normalise `s` to the lower
half of the group order so that each signature has a unique representation. The cross-check test
verifies our signatures against the `k256` reference implementation to confirm correctness.

**Schnorr vs ECDSA — key differences:**

Both are implemented in this project. ECDSA was built first as the more complex algorithm to
implement from scratch; Schnorr is strictly better in most dimensions.

| Property | ECDSA | Schnorr (BIP-340) |
|---|---|---|
| Signature equation | `s = k⁻¹(z + rd) mod n` | `s = k + ex mod n` |
| Batch verification | No | Yes — one EC multiplication per sig amortised |
| Key aggregation | No (without extra protocol) | MuSig2 — native |
| Proof model | Random oracle (ECDLP + ROM) | Clean provably secure in ROM |
| Bitcoin status | Legacy (P2PKH, P2SH) | Taproot (P2TR) — BIP-340 |

The Schnorr implementation follows BIP-340: x-only public keys (32-byte compressed), tagged SHA-256
for the nonce hash (`SHA-256("BIP0340/nonce" ‖ "BIP0340/nonce") ‖ private_key ‖ message`), and
deterministic nonce derivation (no entropy source needed). The demo verifies against BIP-340 test
vectors.

**BLS signatures:**

BLS (Boneh–Lynn–Shacham) over BLS12-381 supports signature aggregation natively at the protocol
level — n signers produce a single constant-size aggregate signature verifiable with n public keys.
Used in Ethereum's consensus layer (validator attestations) and threshold-signing schemes.

| Property | ECDSA/secp256k1 | Schnorr/secp256k1 | BLS/BLS12-381 |
|---|---|---|---|
| Sig size | 64 bytes | 64 bytes | 96 bytes (G2 point) |
| Aggregation | None | MuSig2 (interactive) | Native, non-interactive |
| Pairing needed | No | No | Yes |
| Use case | Ethereum tx, EIP-712 | Bitcoin Taproot, MPC | Eth consensus, threshold |

The implementation uses G1 public keys (48 bytes compressed) and G2 signatures (96 bytes
compressed). The pairing check `e(G, sig_agg) = e(pubkey_agg, H(m))` verifies that the aggregate
signature is valid for the aggregate public key. Hash-to-G2 uses a try-and-increment method: hash
the message with an incrementing counter, interpret as x-coordinate, solve for y, and take the first
valid point. This is simpler than hash-to-curve standards (RFC 9380) but sufficient for educational
purposes.

**Shamir 2-of-3 threshold signing:**

Splits a secp256k1 private key into 3 shares using a degree-1 polynomial `f(x) = secret + a₁·x mod n`
over the scalar field (group order n). Any 2 shares reconstruct the secret via Lagrange interpolation
at x=0. One share reveals nothing (information-theoretic security).

```
Lagrange at x=0: secret = Σ yᵢ · Lᵢ(0) mod n
where Lᵢ(0) = Π_{j≠i} (0 - xⱼ)/(xᵢ - xⱼ) mod n
```

Modular inverse uses Fermat's little theorem (`a⁻¹ = a^(n-2) mod n`, valid when n is prime).
Coefficients are derived deterministically from SHA-256 for reproducibility in the demo. The
reconstruction is verified by deriving the secp256k1 public key and signing with ECDSA.

---

### SHA-256 vs Keccak-256

Both are implemented from spec, but they serve different roles in the ecosystem:

| | SHA-256 | Keccak-256 |
|---|---|---|
| Standard | NIST FIPS 180-4 | Keccak (not NIST SHA-3) |
| Construction | Merkle-Damgård | Sponge (Keccak-f[1600]) |
| Domain byte | N/A | 0x01 (Ethereum variant) |
| Use in Bitcoin | Block hashing, HASH160 | Not used |
| Use in Ethereum | Not used on-chain | `keccak256()` opcode, EIP-712, address derivation |

The Ethereum variant uses domain separation byte `0x01`, distinct from NIST SHA-3 (`0x06`). The
two produce different digests for the same input.

The blockchain uses both algorithms interchangeably as a demo choice; real Bitcoin uses SHA-256
and real Ethereum uses Keccak-256.

---

### RSA (textbook, not PKCS#1)

Textbook RSA: `c = m^e mod n`, `m = c^d mod n`. No OAEP padding, no PKCS#1 v1.5. This is
intentional for clarity — the demo shows the mathematical structure without padding complexity.

For block encoding of text, each chunk is `⌊(n.bits()-1)/8⌋` bytes, ensuring `m < n`. This is
not how PKCS#1 does it (which pads to the full modulus size with structured headers) but it
correctly demonstrates the RSA correctness property.

Modular inverse for key generation uses the extended Euclidean algorithm. Primality testing uses
deterministic Miller-Rabin with the 12 witnesses that cover all `n < 3.3 × 10^24` (Pomerance et
al. 1993) — sufficient for the small primes the demo accepts as CLI input.

---

### AES-128

FIPS 197 compliant: 10 rounds, `SubBytes → ShiftRows → MixColumns → AddRoundKey` (final round
omits MixColumns). `MixColumns` uses GF(2⁸) arithmetic with the AES irreducible polynomial
`x⁸+x⁴+x³+x+1 (0x11b)`.

State is a 4×4 byte matrix indexed `state[row][col]` in column-major byte order (matching FIPS
197 §3.4). The `bytes_to_state` / `state_to_bytes` conversion handles the column-major ordering.

---

### Proof-of-Work blockchain

The chain uses a string concatenation for the block header
(`index ‖ timestamp ‖ data ‖ previous_hash ‖ nonce`), which is much simpler than Bitcoin's
80-byte binary serialisation. Difficulty is a leading-hex-zero count, not Bitcoin's compact target
format.

Merkle root uses SHA-256 over string-encoded hashes (hash-of-hash-strings) rather than
double-SHA-256 over serialised transaction bytes. Sufficient to demonstrate the data structure;
Bitcoin uses double-SHA-256 for TXID computation and a specific leaf/internal node domain
separation that prevents second-preimage attacks on the tree.

The mining nonce is capped at 2,000,000 to stay responsive in WASM. Real mining uses nonce
exhaustion + extraNonce extension.

---

## Planned extensions

| Extension | Module | Key design point |
|---|---|---|
| Schnorr (BIP-340) | `src/schnorr/` | Tagged-hash nonce (BIP-340 test vectors); linear `s = k + ex mod n` |
| BLS signatures | `src/bls/` | BLS12-381 curve; aggregate verify; separate from secp256k1 code |
| Shamir / MPC | `src/mpc/` | 2-of-3 threshold; test share-loss and invalid-share paths |
| ZK attestation | `src/zk/` | Educational Groth16 verifier; prove age > 18 without revealing value |

The ZK extension requires a study step (Groth16 proving system, elliptic curve pairings) before
implementation. Schnorr and Shamir can be built against the existing secp256k1 primitives.
