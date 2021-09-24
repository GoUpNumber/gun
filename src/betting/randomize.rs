use crate::rand_core::{CryptoRng, RngCore};
use olivia_secp256k1::fun::Scalar;

#[derive(Debug, Clone)]
pub struct Randomize {
    pub r1: Scalar,
    pub r2: Scalar,
    pub swap_points: bool,
}

impl Randomize {
    pub fn new(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let r1 = Scalar::random(rng);
        let r2 = Scalar::random(rng);
        let mut byte = [0u8; 1];
        rng.fill_bytes(&mut byte);
        let swap_points = (byte[0] & 0x01) == 1;

        Randomize {
            r1,
            r2,
            swap_points,
        }
    }
}
