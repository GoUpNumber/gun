use chacha20::cipher::StreamCipher;
use olivia_secp256k1::fun::{marker::EvenY, Point};
use std::str::FromStr;

use crate::party::Offer;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct Ciphertext {
    pub public_key: Point<EvenY>,
    pub encrypted_bytes: Vec<u8>,
}

impl Ciphertext {
    pub fn create(
        public_key: Point<EvenY>,
        cipher: &mut impl StreamCipher,
        plaintext: Plaintext,
    ) -> Self {
        let mut encrypted_bytes = crate::encode::serialize(&plaintext);
        cipher.apply_keystream(&mut encrypted_bytes);
        Self {
            public_key,
            encrypted_bytes,
        }
    }

    pub fn to_string(&self) -> String {
        crate::encode::serialize_base2048(self)
    }

    pub fn to_string_padded(&self, pad_to: usize, pad_cipher: &mut impl StreamCipher) -> String {
        let mut bytes = crate::encode::serialize(self);
        if bytes.len() < pad_to {
            let mut padding = vec![0u8; pad_to - bytes.len()];
            pad_cipher.apply_keystream(&mut padding);
            bytes.append(&mut padding);
        }

        base2048::encode(&bytes)
    }

    pub fn decrypt(&self, cipher: &mut impl StreamCipher) -> anyhow::Result<Plaintext> {
        let mut plaintext = self.encrypted_bytes.clone();
        cipher.apply_keystream(&mut plaintext);
        Ok(crate::encode::deserialize::<Plaintext>(&plaintext)?)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum Plaintext {
    Offerv1(Offer),
    Messagev1(String),
}

impl Plaintext {
    pub fn into_offer(self) -> Offer {
        match self {
            Self::Offerv1(offer) => offer,
            _ => panic!("expected offer"),
        }
    }
}

impl FromStr for Ciphertext {
    type Err = crate::encode::DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        crate::encode::deserialize_base2048(s)
    }
}
