use magical::bitcoin::hashes::{sha512, Hash, HashEngine, Hmac, HmacEngine};
use olivia_core::EventId;
use olivia_secp256k1::schnorr_fun::fun::{marker::*, Scalar, XOnly, G};

pub struct KeyPair {
    pub public_key: XOnly,
    pub secret_key: Scalar,
}

pub fn kdf(seed: &[u8; 64], event_id: &EventId, value: u64, index: u32) -> KeyPair {
    let mut proposal_hmac = {
        let mut hmac = HmacEngine::<sha512::Hash>::new(b"bweet-prposal-key");
        hmac.input(&seed[..]);
        let res = Hmac::from_engine(hmac);
        HmacEngine::<sha512::Hash>::new(&res[..])
    };

    proposal_hmac.input(event_id.as_str().as_bytes());
    proposal_hmac.input(value.to_be_bytes().as_ref());
    proposal_hmac.input(index.to_be_bytes().as_ref());
    let res = Hmac::from_engine(proposal_hmac);
    let mut secret_key = Scalar::from_slice_mod_order(&res[..32])
        .expect("is 32 bytes long")
        .mark::<NonZero>()
        .expect("Computationally unreachable");
    let public_key = XOnly::from_scalar_mul(G, &mut secret_key);

    KeyPair {
        public_key,
        secret_key,
    }
}
