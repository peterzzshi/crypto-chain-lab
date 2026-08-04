# Copilot Instructions — encryption-algorithms-demo

## Project Purpose
Educational Rust + WASM app demonstrating cryptographic algorithm steps in the browser.
Showcases Rust for Web3: Rust → WASM is the universal compile target for Solana (BPF), CosmWasm, Polkadot, NEAR, and ZK VMs (Risc0, SP1). The same primitives implemented here power every Ethereum and Bitcoin transaction.

## Architecture
Each algorithm lives in `src/<algo>/` with consistent sub-modules:
`types.rs`, `constants.rs`, `math_utils.rs`, `validation.rs`, `key_generation|compression.rs`, `demo.rs`, `mod.rs`

All WASM bindings are in `src/wasm/mod.rs` as `#[wasm_bindgen]` fns returning JSON strings.
Frontend: `web/ts/` TypeScript compiled to `web/js/`. Types and rendering in `web/ts/ui.ts`.

## Code Standards
- No `unwrap()`/`expect()` except in constant initialisation helpers (document why it cannot fail)
- No panic paths in library code — return `Result<T, String>` at validation boundaries
- Comments only when the code itself cannot convey the intent; no restatements, no multi-line doc blocks
- Functional style: pure functions, encode behaviour in types, keep I/O at the edges
- Tests after feature complete; test behaviour not implementation detail

## Workflow
- One phase per chat; open each chat with: "Check `.github/copilot-instructions.md`"
- Propose WASM API surface + Rust types before implementing each new algorithm
- Analyse neighbouring code when touching a file — clean up and optimise in the same pass
- Skills to load: `rust-pro`, `typescript-dev`, `fp-patterns`, `rust-testing-verification`

## Verification Commands (run manually)
```
cargo fmt --check
cargo clippy -- -D warnings
cargo test
trunk build          # outputs to web/dist/; pre-build hooks run cargo+wasm-bindgen+npm
cd web && npm run typecheck
```

Development server: `trunk serve` (hot reload).

Install trunk: `brew install trunk` (macOS) or binary from github.com/thedodd/trunk/releases.
Install wasm-bindgen-cli: `cargo install --locked wasm-bindgen-cli`

## Roadmap
- [x] RSA (u64 toy keys, step breakdown)
- [x] SHA-256 (full 64-round step breakdown)
- [x] **Phase 1**: secp256k1 ECC key derivation + educational small-curve demo
- [ ] Phase 2: Keccak-256 + Ethereum address derivation pipeline
- [ ] Phase 3: Minimal blockchain — Merkle tree, PoW, ECDSA signing
- [ ] Phase 4: Pluggable algorithm selector across blockchain construction
