use crate::{rand_core::SeedableRng};
use chacha20::{cipher::*, ChaCha20, ChaCha20Rng};
use crate::fun::{g, marker::*, Point, Scalar, G};
use rand::{RngCore, CryptoRng};
use sha2::{
    digest::{
        generic_array::{sequence::Split, typenum::U32},
        Digest,
    },
    Sha512,
};

pub fn ecdh_with_aux(
    keypair: &KeyPair,
    remote: &Point<EvenY>,
    aux: &[u8],
) -> (ChaCha20, ChaCha20Rng) {
    let Y = remote;
    let x = &keypair.secret_key;
    let XY = g!(x * Y).mark::<Normal>();
    let (cipher_key, rng_key) = Split::<u8, U32>::split(
        Sha512::default()
            .chain(XY.to_xonly().as_bytes())
            .chain(aux)
            .finalize(),
    );
    let rng = ChaCha20Rng::from_seed(rng_key.into());
    let cipher = ChaCha20::new(&cipher_key, &[0u8; 12].into());

    (cipher, rng)
}

pub fn ecdh(keypair: &KeyPair, remote: &Point<EvenY>) -> (ChaCha20, ChaCha20Rng) {
    ecdh_with_aux(&keypair, remote, b"")
}


#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct KeyPair {
    pub public_key: Point<EvenY>,
    pub secret_key: Scalar,
}

impl KeyPair {
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        let mut secret_key = Scalar::from_slice_mod_order(&bytes[..32])
            .expect("is 32 bytes long")
            .mark::<NonZero>()?;
        Some(Self::from_secret_key(secret_key))
    }

    pub fn from_secret_key(mut secret_key: Scalar) -> Self {
        let public_key = Point::<EvenY>::from_scalar_mul(G, &mut secret_key);
        KeyPair {
            public_key,
            secret_key,
        }
    }

    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self::from_secret_key(Scalar::random(rng))
    }
}
