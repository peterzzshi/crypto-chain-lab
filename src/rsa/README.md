# RSA

## Key Generation

Given distinct primes p, q:

| Symbol | Definition |
|--------|-----------|
| n | p · q (modulus) |
| φ(n) | (p−1)(q−1) (Euler's totient) |
| e | public exponent: gcd(e, φ(n)) = 1 |
| d | private exponent: e · d ≡ 1 (mod φ(n)), i.e. d = e⁻¹ mod φ(n) |

Public key: **(n, e)** — Private key: **(n, d)**

## Encryption / Decryption

```
c = mᵉ mod n          (encryption)
m = cᵈ mod n          (decryption)
```

**Correctness** (Euler's theorem, gcd(m, n) = 1):

```
cᵈ = (mᵉ)ᵈ = m^(ed) = m^(kφ(n)+1) = (m^φ(n))ᵏ · m ≡ 1ᵏ · m = m (mod n)
```

## Block Encoding

For arbitrary-length plaintext, split into blocks of `block_size = ⌊(n.bits()−1)/8⌋` bytes so that each block m_i < n. Encrypt and decrypt each block independently.

**Constraint:** n > 255 requires p, q > 16.

## Security

Hardness assumption: integer factorisation of n = p·q.
Practical key sizes: 2048-bit n (NIST SP 800-57, 2031+), or 3072-bit for post-2031.
