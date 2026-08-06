# Crypto Chain Lab

Implementing cryptographic primitives **from scratch** in Rust and exposes them as interactive WebAssembly demos — including a fully working Proof-of-Work blockchain built on top of those primitives.

## 🎯 What's inside

| Primitive | What it shows |
|-----------|--------------|
| **RSA** | Key generation, modular exponentiation, encrypt/decrypt |
| **SHA-256** | Message padding, compression rounds, step-by-step state |
| **Keccak-256** | Sponge construction, Keccak-f[1600] permutation |
| **ECC Weierstrass** | Point addition, scalar multiplication on generic curves |
| **secp256k1** | Bitcoin's curve — public key derivation from a private key |
| **ECDSA** | RFC 6979 deterministic signing + verification on secp256k1 |
| **Blockchain (PoW)** | Genesis + mining with SHA-256 or Keccak-256, chain validation, tamper detection |

## 🚀 Quick start

### Interactive web demo

**Live:** https://peterzzshi.github.io/crypto-chain-lab/

Local development:

```bash
# 1. Build WASM + TypeScript
trunk build          # uses Trunk.toml pre-build hook

# 2. Serve
python3 -m http.server 8080 --directory dist
```

### CLI demos

```bash
cargo run -- rsa    --message "Hi" -p 251 -q 241
cargo run -- sha256 --message "Hello, World!"
```

## 📁 Project structure

```
src/
├── common/        shared validation utilities
├── rsa/           RSA from scratch
├── sha256/        SHA-256 from scratch
├── keccak256/     Keccak-256 from scratch
├── ecc/           Weierstrass ECC + secp256k1
├── blockchain/    PoW chain built on the primitives above
│   ├── hash.rs    dispatcher → SHA-256 or Keccak-256
│   ├── mining.rs  nonce loop with educational step output
│   ├── chain.rs   genesis, mine_next_block, validate, tamper
│   └── types.rs   Block, Chain, MineBlockResult, ValidateResult
└── wasm/          wasm-bindgen exports
web/ts/
├── app.ts         entry point, tab/select routing
├── blockchain.ts  stateful blockchain UI
├── demos.ts       primitive demo orchestration
├── wasm.ts        WASM bindings
└── ui.ts          pure HTML builders
tests/
├── rsa/           RSA unit + integration tests
├── ecc/           ECC unit tests
└── blockchain/    blockchain integration tests (24 tests)
```

## 🏗️ Architecture

All cryptographic logic lives in Rust. The TypeScript layer is a thin UI shell:

```
Browser  ←→  TypeScript UI  ←→  WASM (Rust)  ←→  Primitives
```

- **No third-party crypto libraries** — every algorithm is implemented from spec
- **WASM boundary**: all state is serialised as JSON on each call; Rust is stateless
- **Functional style**: pure calculation functions, side effects separated

## 🧪 Tests

```bash
cargo test                           # all suites
cargo test --test blockchain_tests   # PoW chain (24 tests)
cargo test --test rsa_tests          # RSA
cargo test --test ecc_tests          # ECC / secp256k1
```

## 📝 License

MIT
