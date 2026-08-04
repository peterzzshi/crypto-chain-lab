# Encryption Algorithms Demo

A hands-on educational project demonstrating cryptographic algorithms in Rust with step-by-step mathematical explanations.

## 🎯 Overview

This project implements cryptographic algorithms from scratch, showing each computational step to help understand how they work under the hood. Perfect for learning cryptography fundamentals.

**Algorithms Implemented:**
- **RSA** - Public-key encryption (encryption/decryption)
- **SHA-256** - Cryptographic hash function

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/peterzzshi/encryption-algorithms-demo.git
cd encryption-algorithms-demo
cargo build --release
```

### 🌐 Web Demo (Interactive UI)

**Live Demo:** Visit the [GitHub Pages site](https://peterzzshi.github.io/encryption-algorithms-demo/) for the interactive web demo.

#### Local Development

Run the interactive web demo locally with step-by-step visualisations:

```bash
# Build the WebAssembly module
wasm-pack build --target web --out-dir web/pkg

# Install dependencies and build TypeScript
cd web
npm install
npm run build

# Start a local server
python3 -m http.server 8080
```

Then open http://localhost:8080 in your browser!

### Running Demos

#### RSA Encryption

```bash
# Encrypt a number
cargo run -- rsa --message 42 -p 61 -q 53

# Encrypt text
cargo run -- rsa --message "Hi" -p 251 -q 241

# Larger primes for better security demo
cargo run -- rsa --message "Hello" -p 65521 -q 65519
```

**Parameters:**
- `-m, --message` - Message to encrypt (number or text)
- `-p` - First prime number
- `-q` - Second prime number

#### SHA-256 Hashing

```bash
# Hash text
cargo run -- sha256 --message "Hello, World!"

# Hash hex bytes
cargo run -- sha256 --message "48656c6c6f"
```

**Parameters:**
- `-m, --message` - Message to hash (text or hex string)

## 📁 Project Structure

```
encryption-algorithms-demo/
├── .github/
│   └── workflows/
│       └── deploy.yml       # GitHub Pages deployment
├── src/
│   ├── common/              # Shared utilities
│   │   └── validation.rs    # Input validation
│   ├── rsa/                 # RSA implementation
│   │   ├── constants.rs     # Public exponents
│   │   ├── encryption.rs    # Encrypt/decrypt
│   │   ├── key_generation.rs
│   │   ├── math_utils.rs    # Modular arithmetic
│   │   ├── text_encoding.rs
│   │   ├── types.rs         # RSA types
│   │   ├── validation.rs    # Prime validation
│   │   ├── demo.rs          # Demo runner
│   │   └── README.md        # RSA explanation
│   ├── sha256/              # SHA-256 implementation
│   │   ├── constants.rs     # K constants, initial hash
│   │   ├── compression.rs   # Compression function
│   │   ├── preprocessing.rs # Message padding
│   │   ├── math_utils.rs    # Bitwise operations
│   │   ├── types.rs         # SHA types
│   │   ├── validation.rs    # Message validation
│   │   ├── demo.rs          # Demo runner
│   │   └── README.md        # SHA-256 explanation
│   ├── wasm/                # WebAssembly bindings
│   │   └── mod.rs
│   ├── lib.rs               # Library entry
│   └── main.rs              # CLI entry
├── tests/
│   ├── common/              # Common utility tests
│   └── rsa/                 # RSA tests
├── web/                     # Web demo (GitHub Pages)
│   ├── index.html
│   ├── css/
│   │   └── styles.css
│   ├── ts/                  # TypeScript source
│   │   ├── app.ts           # Application entry
│   │   ├── demos.ts         # Demo orchestration
│   │   ├── ui.ts            # UI rendering (pure)
│   │   ├── utils.ts         # Utilities (pure)
│   │   └── wasm.ts          # WASM bindings
│   ├── js/                  # Compiled JavaScript (generated)
│   └── pkg/                 # WASM package (generated)
└── README.md
```

## 🏗️ Architecture

### Design Principles

This project follows **functional programming principles**:
- ✅ Pure calculation functions (no mutations)
- ✅ Side effects (printing) separated from calculations
- ✅ Algorithm-specific code isolated in modules
- ✅ Minimal shared utilities in `common/`

### Module Organization

```
┌─────────────────────────────────────────────────────────┐
│  src/common/                                            │
│  • Shared utilities (validation, hex formatting)       │
└─────────────────────────────────────────────────────────┘
                         ▲          ▲
                         │          │
            ┌────────────┴──────────┴────────────┐
            │                                    │
┌───────────▼─────────────┐        ┌─────────────▼───────────┐
│  src/rsa/               │        │  src/sha256/            │
│  • Modular arithmetic   │        │  • Bitwise operations   │
│  • Key generation       │        │  • Message padding      │
│  • Encrypt/decrypt      │        │  • Compression function │
│  • Text encoding        │        │  • Hash computation     │
└─────────────────────────┘        └─────────────────────────┘
```

### What's Common vs Algorithm-Specific

**Common (`src/common/`):**
- `format_bytes_as_hex()` - Hex string conversion
- `validate_non_empty_message()` - Empty checks
- `validate_message_length()` - Length validation
- `is_printable_ascii()` - ASCII validation

**Algorithm-Specific (stays separate):**
- `math_utils.rs` - Different per algorithm (modular arithmetic vs bitwise ops)
- `constants.rs` - Algorithm parameters (exponents vs K values)
- `types.rs` - Algorithm-specific types (KeyPair vs Hash)
- `validation.rs` - Algorithm rules (prime checks vs message format)

### Web Architecture

The web demo follows the same functional programming principles:

```
┌─────────────────────────────────────────────────────────┐
│  web/ts/                                                │
├─────────────────────────────────────────────────────────┤
│  utils.ts   │ Pure: DOM queries, validation, parsing   │
│  ui.ts      │ Pure: HTML builders, render functions    │
│  wasm.ts    │ WASM bindings with encapsulated state    │
│  demos.ts   │ Demo orchestration, input/output flow    │
│  app.ts     │ Entry point, event listener setup        │
└─────────────────────────────────────────────────────────┘
```

**Key patterns:**
- **Immutable interfaces** - All data structures use `readonly` properties
- **Pure functions** - HTML builders and validators have no side effects
- **Closure-based state** - WASM module state encapsulated in closure (not mutable global)
- **Type safety** - TypeScript strict mode with comprehensive type annotations
- **Separated concerns** - Side effects (DOM manipulation) isolated from pure logic

**State Management:**
The WASM module uses a closure pattern to avoid mutable globals:
```typescript
// ❌ Avoid: Mutable global state
let wasmModule: WasmModule | null = null;

// ✅ Prefer: Closure-based immutable state
const createWasmState = (): WasmState => {
    let module: WasmModule | undefined;
    return {
        isReady: () => module !== undefined,
        get: () => { /* ... */ },
        initialise: (wasm) => { /* ... */ }
    };
};
```

**Build Process:**
1. TypeScript (`.ts`) files compiled to JavaScript (`.js`) via `tsc`
2. WASM module built via `wasm-pack` → `web/pkg/`
3. HTML imports compiled JS modules directly

## 🚀 Deployment

The project automatically deploys to GitHub Pages via GitHub Actions when you push to the `main` branch.

**To enable deployment on your fork:**
1. Go to repository **Settings** → **Pages**
2. Under **Source**, select **GitHub Actions**
3. Push to `main` to trigger deployment

The site will be available at `https://<username>.github.io/<repository-name>/`

## 🧪 Testing

Run all tests:
```bash
cargo test
```

Run specific test suites:
```bash
cargo test --test rsa_tests        # RSA tests only
cargo test --test common_tests     # Common utility tests
cargo test rsa::math_utils_tests   # Specific module
```

## 📚 Documentation

Each algorithm has detailed documentation:

- **[RSA README](src/rsa/README.md)** - Complete mathematical walkthrough with worked examples
- **[SHA-256 README](src/sha256/README.md)** - Hash algorithm explanation

## 🔑 Key Insights

### RSA
- **Demo uses small primes** (3, 11, 61, etc.) for educational clarity
- **Real-world uses 2048-bit primes** (617+ digits) - computationally infeasible to crack
- Demonstrates asymmetric cryptography: public key encrypts, private key decrypts

### SHA-256
- **One-way function** - cannot reverse the hash to get original message
- **Fixed output size** - always 256 bits (64 hex characters)
- Used in Bitcoin, TLS, digital signatures

## 📝 License

MIT License - See [LICENSE](LICENSE) file for details
