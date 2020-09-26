use olivia_secp256k1::schnorr_fun::fun::{g, marker::*, Point, Scalar, XOnly};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use sha2::{digest::Digest, Sha256};

#[derive(Debug, Clone)]
pub struct KeyPair {
    pub secret_key: Scalar,
    pub public_key: Point,
}

pub fn generate_prng(keypair: &KeyPair, remote: &XOnly) -> ChaCha20Rng {
    let Y = remote.to_point();
    let XY = g!(keypair.secret_key * Y).mark::<Normal>();
    let sk = Sha256::default().chain(XY.to_xonly().as_bytes()).finalize();
    ChaCha20Rng::from_seed(sk.into())
}
