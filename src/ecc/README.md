# Elliptic Curve Cryptography

## Short Weierstrass Form

A non-singular elliptic curve over prime field 𝔽ₚ:

```
E(𝔽ₚ): y² ≡ x³ + ax + b (mod p)
```

**Non-singularity:** 4a³ + 27b² ≢ 0 (mod p)

## Group Law

Let P = (x₁, y₁), Q = (x₂, y₂) ∈ E(𝔽ₚ), plus the point at infinity 𝒪 (identity).

**Point addition** P + Q (P ≠ Q):

```
λ = (y₂ − y₁)(x₂ − x₁)⁻¹ mod p
x₃ = λ² − x₁ − x₂ mod p
y₃ = λ(x₁ − x₃) − y₁ mod p
```

**Point doubling** 2P (P = Q, y₁ ≠ 0):

```
λ = (3x₁² + a)(2y₁)⁻¹ mod p
x₃ = λ² − 2x₁ mod p
y₃ = λ(x₁ − x₃) − y₁ mod p
```

If y₁ = 0: 2P = 𝒪.  Negation: −P = (x, −y mod p).

## Scalar Multiplication

Q = k · G computed by the **double-and-add** method (binary left-to-right):

```
R ← 𝒪,  T ← G
for i = 0 to bit_len(k)−1:
    if k_i = 1: R ← R + T
    T ← 2T
return R
```

Cost: O(log k) doublings + up to O(log k) additions.

## Key Derivation

| Symbol | Definition |
|--------|-----------|
| p | prime field modulus |
| G | generator (base point) of prime order n |
| n | group order: n · G = 𝒪 |
| k | private key: k ∈ [1, n−1] |
| Q = k·G | public key |

## secp256k1 (SECG SEC 2 v2.0)

```
a = 0,  b = 7
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
```

Used in Bitcoin (BIP-340 Schnorr, ECDSA) and Ethereum (EIP-155 ECDSA).

## Public Key Encoding (SEC 1 v2.0 §2.3.3)

| Format | Bytes | Encoding |
|--------|-------|---------|
| Compressed | 33 | 02‖x (y even) or 03‖x (y odd) |
| Uncompressed | 65 | 04‖x‖y |

## Group Order (Weierstrass Demo)

For p ≤ 65521, group order n = #E(𝔽ₚ) is computed by point enumeration using Euler's criterion:

```
n = 1 +  Σ_{x=0}^{p−1} (1 + legendre(x³+ax+b, p))

legendre(a, p) = aᵉˣᵖ mod p,  exp = (p−1)/2
               = 1  if a is a non-zero QR mod p
               = 0  if a ≡ 0
               = p−1 otherwise
```

Complexity: O(p · log p) modular exponentiations. Restricted to p ≤ 65521 in this demo.
