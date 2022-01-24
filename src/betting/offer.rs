use crate::{betting::*, change::Change};
use bdk::{
    bitcoin,
    bitcoin::{Amount, Transaction},
};
use chacha20::cipher::StreamCipher;
use olivia_secp256k1::fun::{marker::EvenY, Point};
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Offer {
    pub inputs: Vec<SignedInput>,
    pub change: Option<Change>,
    pub choose_right: bool,
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
    pub value: Amount,
}

pub struct ValidatedOffer {
    pub bet_id: BetId,
    pub bet: Bet,
}

impl ValidatedOffer {
    pub fn tx(&self) -> Transaction {
        self.bet.psbt.clone().extract_tx()
    }
}

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

    pub fn to_base2048_string(&self) -> String {
        crate::encode::serialize_base2048(self)
    }

    pub fn to_string_padded(
        &self,
        pad_to: usize,
        pad_cipher: &mut impl StreamCipher,
    ) -> (String, usize) {
        let mut bytes = crate::encode::serialize(self);
        let mut overflow = 0;
        match bytes.len() {
            len if len < pad_to => {
                let mut padding = vec![0u8; pad_to - len];
                pad_cipher.apply_keystream(&mut padding);
                bytes.append(&mut padding);
            }
            len => overflow = len - pad_to,
        }
        (base2048::encode(&bytes), overflow)
    }

    pub fn decrypt(&self, cipher: &mut impl StreamCipher) -> anyhow::Result<Plaintext> {
        let mut plaintext = self.encrypted_bytes.clone();
        cipher.apply_keystream(&mut plaintext);
        Ok(crate::encode::deserialize::<Plaintext>(&plaintext)?)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum Plaintext {
    Offerv1 {
        offer: Offer,
        message: Option<String>,
    },
    Messagev1(String),
}

impl Plaintext {
    pub fn into_offer(self) -> Offer {
        match self {
            Self::Offerv1 { offer, .. } => offer,
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::keychain::KeyPair;
    use bdk::bitcoin::{Address, OutPoint};
    use chacha20::{cipher::NewCipher, ChaCha20};
    use core::str::FromStr;
    use olivia_secp256k1::ecdsa_fun::Signature;

    fn test_offer() -> (Point<EvenY>, Offer) {
        let offer_keypair = KeyPair::from_slice(&[42u8; 32]).unwrap();
        let public_key = offer_keypair.public_key;
        (
            public_key,
            Offer {
                inputs: vec![
                    SignedInput {
                        outpoint: OutPoint::default(),
                        witness: Witness::P2wpkh {
                            key: Point::random(&mut rand::thread_rng()).into(),
                            signature: Signature::from_bytes([43u8; 64]).unwrap(),
                        },
                    },
                    SignedInput {
                        outpoint: OutPoint::default(),
                        witness: Witness::P2wpkh {
                            key: Point::random(&mut rand::thread_rng()).into(),
                            signature: Signature::from_bytes([43u8; 64]).unwrap(),
                        },
                    },
                ],
                change: None,
                choose_right: false,
                value: Amount::from_str_with_denomination("1 BTC").unwrap(),
            },
        )
    }

    #[test]
    pub fn encrypt_decrypt_roundtrip() {
        let (public_key, offer) = test_offer();
        let mut cipher1 = ChaCha20::new(&[2u8; 32].into(), &[2u8; 12].into());
        let mut cipher2 = ChaCha20::new(&[2u8; 32].into(), &[2u8; 12].into());

        let encrypted_offer = Ciphertext::create(
            public_key,
            &mut cipher1,
            Plaintext::Offerv1 {
                offer: offer.clone(),
                message: None,
            },
        );

        assert_eq!(
            encrypted_offer.decrypt(&mut cipher2).unwrap().into_offer(),
            offer
        );
    }

    #[test]
    fn offer_with_message_attached() {
        let (public_key, offer) = test_offer();
        let mut cipher1 = ChaCha20::new(&[2u8; 32].into(), &[2u8; 12].into());
        let mut cipher2 = ChaCha20::new(&[2u8; 32].into(), &[2u8; 12].into());

        let encrypted_offer = Ciphertext::create(
            public_key,
            &mut cipher1,
            Plaintext::Offerv1 {
                offer: offer.clone(),
                message: Some("a message".into()),
            },
        );

        if let Plaintext::Offerv1 {
            offer: decrypted_offer,
            message,
        } = encrypted_offer.decrypt(&mut cipher2).unwrap()
        {
            assert_eq!(decrypted_offer, offer);
            assert_eq!(message, Some("a message".into()));
        } else {
            panic!("expected offer");
        }
    }

    #[test]
    pub fn encrypt_decrypt_padded_offer_of_different_sizes() {
        let (public_key, offer) = test_offer();
        let encrypted_offer1 = {
            let mut cipher1 = ChaCha20::new(&[2u8; 32].into(), &[2u8; 12].into());
            let mut cipher2 = ChaCha20::new(&[2u8; 32].into(), &[2u8; 12].into());

            let encrypted_offer = Ciphertext::create(
                public_key,
                &mut cipher1,
                Plaintext::Offerv1 {
                    offer: offer.clone(),
                    message: None,
                },
            );
            let (enc_string_offer, _) = encrypted_offer.to_string_padded(385, &mut cipher1);
            let decrypted_offer = Ciphertext::from_str(&enc_string_offer)
                .unwrap()
                .decrypt(&mut cipher2)
                .unwrap()
                .into_offer();
            assert_eq!(decrypted_offer, offer);
            enc_string_offer
        };

        let encrypted_offer2 = {
            let mut cipher1 = ChaCha20::new(&[3u8; 32].into(), &[2u8; 12].into());
            let mut cipher2 = ChaCha20::new(&[3u8; 32].into(), &[2u8; 12].into());

            let mut offer = offer.clone();
            offer.change = Some(Change::new(
                5_000,
                Address::from_str("bc1qwxhv5aqc6xahxedh7m2wm333lgkjpmllz4j248")
                    .unwrap()
                    .script_pubkey(),
            ));
            let encrypted_offer = Ciphertext::create(
                public_key,
                &mut cipher1,
                Plaintext::Offerv1 {
                    offer: offer.clone(),
                    message: None,
                },
            );
            let (enc_string_offer, _) = encrypted_offer.to_string_padded(385, &mut cipher1);
            let decrypted_offer = Ciphertext::from_str(&enc_string_offer)
                .unwrap()
                .decrypt(&mut cipher2)
                .unwrap()
                .into_offer();
            assert_eq!(decrypted_offer, offer);
            enc_string_offer
        };

        assert_eq!(
            encrypted_offer1.chars().count(),
            encrypted_offer2.chars().count(),
        );
    }
}
