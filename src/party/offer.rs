use super::{randomize::Randomize, BetArgs, Either};
use crate::{
    bet::Bet,
    bet_database::{BetId, BetState},
    change::Change,
    ciphertext::{Ciphertext, Plaintext},
    keychain::KeyPair,
    party::{proposal::Proposal, JointOutput, Party},
    FeeSpec, OracleEvent, OracleInfo, ValueChoice,
};
use anyhow::{anyhow, Context};
use bdk::{
    bitcoin::{self, secp256k1, Amount, Transaction},
    database::BatchDatabase,
    descriptor::ExtendedDescriptor,
    miniscript::DescriptorTrait,
    wallet::{tx_builder::TxOrdering, IsDust},
    SignOptions,
};
use chacha20::cipher::StreamCipher;
use olivia_secp256k1::{
    ecdsa_fun,
    fun::{marker::*, Point, XOnly},
};
use std::convert::TryInto;

pub type OfferId = XOnly;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct SignedInput {
    pub outpoint: bdk::bitcoin::OutPoint,
    pub witness: Witness,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum Witness {
    P2wpkh {
        key: secp256k1::PublicKey,
        // using ecdsa_fun::Signature here ebcause it serializes to 64 bytes rather than DER
        signature: ecdsa_fun::Signature,
    },
}

impl Witness {
    pub fn encode(&self) -> Vec<Vec<u8>> {
        match self {
            Witness::P2wpkh { key, signature } => {
                let mut sig_bytes = secp256k1::Signature::from_compact(&signature.to_bytes())
                    .unwrap()
                    .serialize_der()
                    .to_vec();
                sig_bytes.push(0x01);
                let pk_bytes = key.serialize().to_vec();
                vec![sig_bytes, pk_bytes]
            }
        }
    }

    pub fn decode_p2wpkh(mut w: Vec<Vec<u8>>) -> Option<Self> {
        let key_bytes = w.pop()?;
        let mut sig_bytes = w.pop()?;
        let _sighash = sig_bytes.pop()?;
        let signature = secp256k1::Signature::from_der(&sig_bytes).ok()?.into();
        let key = secp256k1::PublicKey::from_slice(&key_bytes).ok()?;
        Some(Witness::P2wpkh { key, signature })
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Offer {
    pub inputs: Vec<SignedInput>,
    pub change: Option<Change>,
    pub choose_right: bool,
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
    pub value: Amount,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LocalOffer {
    pub proposal: Proposal,
    pub offer: Offer,
    pub keypair: KeyPair,
    pub tx: Transaction,
    pub joint_output: ExtendedDescriptor,
}

impl<D: BatchDatabase> Party<bdk::blockchain::EsploraBlockchain, D> {
    pub fn generate_offer_with_oracle_event(
        &self,
        proposal: Proposal,
        choose_right: bool,
        oracle_event: OracleEvent,
        oracle_info: OracleInfo,
        args: BetArgs<'_, '_>,
        fee_spec: FeeSpec,
    ) -> anyhow::Result<(Bet, Offer, Point<EvenY>, impl StreamCipher)> {
        let remote_public_key = &proposal.public_key;
        let event_id = &oracle_event.event.id;
        if event_id.n_outcomes() != 2 {
            return Err(anyhow!(
                "Cannot make a bet on {} since it isn't binary",
                event_id
            ));
        }

        let anticipated_attestations = oracle_event
            .anticipate_attestations_olivia_v1(&oracle_info.oracle_keys.olivia_v1.ok_or(anyhow!("Oracle {} does not support olivia_v1"))?, 0)
            .ok_or(anyhow!("Cannot make bet on {} since {} doesn't support olivia_v1 attestation for this event", event_id, oracle_info.id))?
            [..2]
            .try_into()
            .unwrap();

        let local_keypair = self.keychain.keypair_for_offer(&proposal);
        let (cipher, mut rng) = crate::ecdh::ecdh(&local_keypair, remote_public_key);

        let remote_public_key = proposal.public_key;
        let randomize = Randomize::new(&mut rng);

        let joint_output = JointOutput::new(
            [remote_public_key, local_keypair.public_key],
            Either::Right(local_keypair.secret_key),
            anticipated_attestations,
            choose_right,
            randomize,
        );

        let mut builder = self.wallet.build_tx();
        builder
            .ordering(TxOrdering::Bip69Lexicographic)
            .enable_rbf();

        let output_script = joint_output.descriptor().script_pubkey();

        match args.value {
            ValueChoice::All => {
                builder.drain_wallet().drain_to(output_script.clone());
            }
            ValueChoice::Amount(amount) => {
                let bet_value = amount + proposal.value;
                builder.add_recipient(output_script.clone(), bet_value.as_sat());
            }
        }

        fee_spec.apply_to_builder(self.wallet.client(), &mut builder)?;

        args.apply_args(self.bet_db(), &mut builder)?;

        let mut input_value = 0;
        for proposal_input in &proposal.inputs {
            let psbt_input = self
                .p2wpkh_outpoint_to_psbt_input(*proposal_input)
                .context("retrieving proposal input")?;
            input_value += psbt_input.witness_utxo.as_ref().unwrap().value;
            builder.add_foreign_utxo(
                *proposal_input,
                psbt_input,
                // p2wpkh wieght
                4 + 1 + 73 + 33,
            )?;
        }

        let proposal_excess = input_value
            .checked_sub(proposal.value.as_sat())
            .ok_or(anyhow!(
                "proposal input value {} is less than proposal value {}",
                input_value,
                proposal.value
            ))?;

        if !proposal_excess.is_dust() {
            let change_script = proposal.change_script.as_ref().ok_or(anyhow!(
                "proposal had excess coins but did not provide change address"
            ))?;
            builder.add_recipient(change_script.clone().into(), proposal_excess);
        }

        let (mut psbt, _tx_details) = builder
            .finish()
            .context("Unable to create offer transaction")?;

        // the inputs we own have witnesses
        let my_input_indexes = psbt
            .global
            .unsigned_tx
            .input
            .iter()
            .enumerate()
            .filter(|(_, input)| !proposal.inputs.contains(&input.previous_output))
            .map(|(i, _)| i)
            .collect::<Vec<_>>();

        let is_final = self
            .wallet
            .sign(&mut psbt, SignOptions::default())
            .context("Unable to sign offer transaction")?;

        if is_final {
            // the only reason it would be final is that the wallet is doing a bet with itself
            return Err(anyhow!("sorry you can't do bets with yourself yet!"));
        }

        let (vout, txout) = psbt
            .global
            .unsigned_tx
            .output
            .iter()
            .enumerate()
            .find(|(_i, txout)| &txout.script_pubkey == &output_script)
            .expect("The bet output must be in there");

        let joint_output_value = Amount::from_sat(txout.value);
        let local_value = joint_output_value - proposal.value;

        let signed_inputs: Vec<SignedInput> = my_input_indexes
            .iter()
            .cloned()
            .map(|i| {
                let txin = &psbt.global.unsigned_tx.input[i];
                let psbt_input = &psbt.inputs[i];
                let witness = psbt_input
                    .final_script_witness
                    .clone()
                    .expect("we added this input so we should have signed it");

                SignedInput {
                    outpoint: txin.previous_output,
                    witness: Witness::decode_p2wpkh(witness)
                        .expect("we signed it so it must be p2wpkh"),
                }
            })
            .collect();

        let mut change = None;

        for output in &psbt.global.unsigned_tx.output {
            if self.wallet.is_mine(&output.script_pubkey)? {
                change = Some(Change::new(output.value, output.script_pubkey.clone()));
            }
        }

        let offer = Offer {
            change,
            inputs: signed_inputs,
            choose_right,
            value: local_value,
        };
        let bet = Bet {
            psbt,
            my_input_indexes,
            vout: vout as u32,
            joint_output: joint_output.clone(),
            oracle_id: oracle_info.id,
            oracle_event,
            local_value,
            joint_output_value,
            i_chose_right: choose_right,
            tags: args.tags,
        };

        Ok((bet, offer, local_keypair.public_key, cipher))
    }

    pub fn save_and_encrypt_offer(
        &self,
        bet: Bet,
        offer: Offer,
        message: Option<String>,
        local_public_key: Point<EvenY>,
        cipher: &mut impl StreamCipher,
    ) -> anyhow::Result<(BetId, Ciphertext)> {
        let encrypted_offer = Ciphertext::create(
            local_public_key,
            cipher,
            Plaintext::Offerv1 {
                offer: offer.clone(),
                message,
            },
        );
        let bet_id = self.bet_db.insert_bet(BetState::Offered {
            bet,
            encrypted_offer: encrypted_offer.clone(),
        })?;
        Ok((bet_id, encrypted_offer))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::keychain::KeyPair;
    use bdk::bitcoin::{Address, OutPoint};
    use chacha20::{cipher::NewCipher, ChaCha20};
    use core::str::FromStr;

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
                            signature: ecdsa_fun::Signature::from_bytes([43u8; 64]).unwrap(),
                        },
                    },
                    SignedInput {
                        outpoint: OutPoint::default(),
                        witness: Witness::P2wpkh {
                            key: Point::random(&mut rand::thread_rng()).into(),
                            signature: ecdsa_fun::Signature::from_bytes([43u8; 64]).unwrap(),
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
