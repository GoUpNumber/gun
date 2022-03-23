use crate::{betting::Proposal, hex};
use bdk::bitcoin::hashes::{sha512, Hash, HashEngine, Hmac, HmacEngine};
use olivia_secp256k1::schnorr_fun::fun::{marker::*, Point, Scalar, G};
use rand::{CryptoRng, RngCore};

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ProtocolSecret {
    Bytes(#[serde(with = "crate::serde_hacks::BigArray")] [u8; 64]),
}

impl core::str::FromStr for ProtocolSecret {
    type Err = olivia_secp256k1::hex::HexError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        Ok(ProtocolSecret::Bytes(olivia_secp256k1::hex::decode_array(
            string,
        )?))
    }
}

impl core::fmt::Display for ProtocolSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolSecret::Bytes(bytes) => write!(f, "{}", hex::encode(&bytes[..])),
        }
    }
}

impl From<ProtocolSecret> for Keychain {
    fn from(protocol_secret: ProtocolSecret) -> Self {
        match protocol_secret {
            ProtocolSecret::Bytes(bytes) => Keychain::new(bytes),
        }
    }
}

pub struct Keychain {
    proposal_hmac: HmacEngine<sha512::Hash>,
    offer_hmac: HmacEngine<sha512::Hash>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct KeyPair {
    pub public_key: Point<EvenY>,
    pub secret_key: Scalar,
}

impl KeyPair {
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        let secret_key = Scalar::from_slice_mod_order(&bytes[..32])
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

impl Keychain {
    pub fn new(seed: [u8; 64]) -> Self {
        let proposal_hmac = {
            let mut hmac = HmacEngine::<sha512::Hash>::new(b"gun-proposal");
            hmac.input(&seed[..]);
            let res = Hmac::from_engine(hmac);
            HmacEngine::<sha512::Hash>::new(&res[..])
        };

        let offer_hmac = {
            let mut hmac = HmacEngine::<sha512::Hash>::new(b"gun-offer");
            hmac.input(&seed[..]);
            let res = Hmac::from_engine(hmac);
            HmacEngine::<sha512::Hash>::new(&res[..])
        };

        Self {
            proposal_hmac,
            offer_hmac,
        }
    }

    /// TODO: use the versioned proposal here
    /// DONOTMERGE LIKE THIS
    pub fn get_key_for_proposal(&self, proposal: &Proposal) -> KeyPair {
        let mut proposal = proposal.clone();
        proposal.public_key = crate::placeholder_point();
        let mut proposal_hmac = self.proposal_hmac.clone();
        let bin = crate::encode::serialize(&proposal);
        proposal_hmac.input(&bin[..]);
        let res = Hmac::from_engine(proposal_hmac);
        let keypair = KeyPair::from_slice(&res[..]).expect("computationally unreachable");
        proposal.public_key = keypair.public_key;
        keypair
    }

    pub fn keypair_for_offer(&self, proposal: &Proposal) -> KeyPair {
        let mut offer_hmac = self.offer_hmac.clone();
        let bin = crate::encode::serialize(proposal);
        offer_hmac.input(&bin[..]);
        let res = Hmac::from_engine(offer_hmac);
        KeyPair::from_slice(&res[..]).expect("computationally unreachable")
    }
}
