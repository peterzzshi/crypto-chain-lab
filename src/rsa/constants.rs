// Fermat primes (2^k+1); 65537 is the PKCS/OpenSSL/TLS standard. Ordered smallest-first for fastest encryption.
pub const COMMON_PUBLIC_EXPONENTS: [u64; 8] = [3, 5, 7, 11, 13, 17, 257, 65537];
