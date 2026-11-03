# Agent Instructions

Educational cryptography demo in Rust + WebAssembly.

## Code Style

- **Functional style:** Prefer `map`, `filter`, `fold` over explicit loops where clear. Use iterators, avoid mutable state when practical.
- **Idiomatic Rust:** Follow Clippy suggestions, use `?` for error propagation, leverage type system for correctness.
- **Clarity over performance:** Affine coordinates chosen over projective. Educational demonstration, not production optimization.
- **Educational visualization:** Algorithms expose `*_with_steps` variants for step-by-step output.

## Testing

- Run `cargo test` and `cargo clippy` before completion — zero warnings required.
- Cross-check against known vectors: ECDSA uses k256 crate, AES/SHA-256 use NIST test vectors.
- Write tests for new functionality.

## WASM Boundary

- All WASM functions return JSON-serializable types only.
- Never expose raw Rust structs across the boundary.
- Use `wasm-bindgen` with serde for serialization.

## Git Workflow

- User commits manually — do not auto-commit.

## Documentation

- Read `ARCHITECTURE.md` before making algorithm changes — documents design decisions and tradeoffs.
- Keep `ARCHITECTURE.md` factual: implementation choices, measured results only.
- No interview narratives or production extrapolation in public repo.
