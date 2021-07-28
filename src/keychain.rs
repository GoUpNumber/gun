use crate::{
    bitcoin::{
        hashes::{sha512, Hash, HashEngine, Hmac, HmacEngine},
        util::bip32::ExtendedPrivKey,
        Network,
    },
    party::Proposal,
};
use olivia_secp256k1::schnorr_fun::fun::{marker::*, Point, Scalar, G};

pub struct Keychain {
    seed: [u8; 64],
    proposal_hmac: HmacEngine<sha512::Hash>,
    offer_hmac: HmacEngine<sha512::Hash>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct KeyPair {
    pub public_key: Point<EvenY>,
    pub secret_key: Scalar,
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
            seed,
            proposal_hmac,
            offer_hmac,
        }
    }

    pub fn main_wallet_xprv(&self, network: Network) -> ExtendedPrivKey {
        ExtendedPrivKey::new_master(network, &self.seed).unwrap()
    }

    pub fn get_key_for_proposal(&self, proposal: &Proposal) -> KeyPair {
        let mut proposal = proposal.clone();
        proposal.public_key = crate::placeholder_point();
        let mut proposal_hmac = self.proposal_hmac.clone();
        let bin = crate::encode::serialize(&proposal);
        proposal_hmac.input(&bin[..]);
        let res = Hmac::from_engine(proposal_hmac);
        let keypair = Self::keypair_from_slice(&res[..]);
        proposal.public_key = keypair.public_key;
        keypair
    }

    pub fn keypair_for_offer(&self, proposal: &Proposal) -> KeyPair {
        let mut offer_hmac = self.offer_hmac.clone();
        let bin = crate::encode::serialize(proposal);
        offer_hmac.input(&bin[..]);
        let res = Hmac::from_engine(offer_hmac);
        Self::keypair_from_slice(&res[..])
    }

    fn keypair_from_slice(hmac: &[u8]) -> KeyPair {
        let mut secret_key = Scalar::from_slice_mod_order(&hmac[..32])
            .expect("is 32 bytes long")
            .mark::<NonZero>()
            .expect("Computationally unreachable");
        let public_key = Point::<EvenY>::from_scalar_mul(G, &mut secret_key);
        KeyPair {
            public_key,
            secret_key,
        }
    }
}
