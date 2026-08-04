use num_bigint::BigUint;

#[derive(Clone)]
pub struct RsaKeyPair {
    pub public_key: RsaPublicKey,
    pub private_key: RsaPrivateKey,
}

#[derive(Clone)]
pub struct RsaPublicKey {
    pub n: BigUint,
    pub e: BigUint,
}

#[derive(Clone)]
pub struct RsaPrivateKey {
    pub n: BigUint,
    pub d: BigUint,
}
