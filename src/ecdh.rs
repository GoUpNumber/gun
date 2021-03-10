use crate::{keychain::KeyPair, rand_core::SeedableRng};
use chacha20::{cipher::*, ChaCha20, ChaCha20Rng};
use olivia_secp256k1::schnorr_fun::fun::{g, marker::*, Point};
use sha2::{
    digest::{
        generic_array::{sequence::Split, typenum::U32},
        Digest,
    },
    Sha512,
};

pub fn ecdh(keypair: &KeyPair, remote: &Point<EvenY>) -> (ChaCha20, ChaCha20Rng) {
    let Y = remote;
    let x = &keypair.secret_key;
    let XY = g!(x * Y).mark::<Normal>();
    let (cipher_key, rng_key) =
        Split::<u8, U32>::split(Sha512::default().chain(XY.to_xonly().as_bytes()).finalize());
    let rng = ChaCha20Rng::from_seed(rng_key.into());
    let cipher = ChaCha20::new(&cipher_key, &[0u8; 12].into());

    (cipher, rng)
}
