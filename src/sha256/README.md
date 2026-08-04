# SHA-256 (FIPS 180-4)

## Preprocessing

Pad message M to length ≡ 448 (mod 512) bits:

```
M ‖ 1 ‖ 0…0 ‖ len(M)₆₄
```

where len(M)₆₄ is the original bit length as a 64-bit big-endian word.
Divide the padded message into N 512-bit blocks M⁽¹⁾, …, M⁽ᴺ⁾.

## Initial Hash Values (FIPS 180-4 §5.3.3)

Fractional parts of √p for the first 8 primes p:

```
H₀⁽⁰⁾ = 6a09e667    H₁⁽⁰⁾ = bb67ae85    H₂⁽⁰⁾ = 3c6ef372    H₃⁽⁰⁾ = a54ff53a
H₄⁽⁰⁾ = 510e527f    H₅⁽⁰⁾ = 9b05688c    H₆⁽⁰⁾ = 1f83d9ab    H₇⁽⁰⁾ = 5be0cd19
```

## Round Constants (FIPS 180-4 §4.2.2)

K[t] = fractional part of ∛pₜ for the first 64 primes pₜ (see `src/sha256/constants.rs`).

## Message Schedule (§6.2.2)

For each block M⁽ⁱ⁾, form 64 words W[0..63]:

```
W[t] = M[t]                                              0 ≤ t ≤ 15
W[t] = σ₁(W[t−2]) + W[t−7] + σ₀(W[t−15]) + W[t−16]   16 ≤ t ≤ 63
```

## Compression Function (§6.2.2)

Initialise working variables a…h ← H₀…H₇⁽ⁱ⁻¹⁾. For t = 0…63:

```
T₁ = h + Σ₁(e) + Ch(e,f,g) + K[t] + W[t]
T₂ = Σ₀(a) + Maj(a,b,c)
h←g, g←f, f←e, e←d+T₁, d←c, c←b, b←a, a←T₁+T₂
```

Add back: H_j⁽ⁱ⁾ = H_j⁽ⁱ⁻¹⁾ + (corresponding working variable), all mod 2³².

## Logical Functions

| Symbol | Definition |
|--------|-----------|
| Ch(x,y,z) | (x ∧ y) ⊕ (¬x ∧ z) |
| Maj(x,y,z) | (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z) |
| Σ₀(x) | ROTR²(x) ⊕ ROTR¹³(x) ⊕ ROTR²²(x) |
| Σ₁(x) | ROTR⁶(x) ⊕ ROTR¹¹(x) ⊕ ROTR²⁵(x) |
| σ₀(x) | ROTR⁷(x) ⊕ ROTR¹⁸(x) ⊕ SHR³(x) |
| σ₁(x) | ROTR¹⁷(x) ⊕ ROTR¹⁹(x) ⊕ SHR¹⁰(x) |

## Digest

```
H = H₀⁽ᴺ⁾ ‖ H₁⁽ᴺ⁾ ‖ … ‖ H₇⁽ᴺ⁾   (256 bits)
```
