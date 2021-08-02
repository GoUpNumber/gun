use crate::{
    bet::Bet,
    bet_database::{BetId, BetState},
    change::Change,
    keychain::KeyPair,
    party::{proposal::Proposal, JointOutput, Party},
    FeeSpec, OracleEvent, OracleInfo, ValueChoice,
};
use anyhow::{anyhow, Context};
use bdk::{
    bitcoin::{self, Amount, Transaction},
    database::BatchDatabase,
    descriptor::ExtendedDescriptor,
    miniscript::DescriptorTrait,
    wallet::{tx_builder::TxOrdering, IsDust},
    SignOptions,
};
use chacha20::cipher::StreamCipher;
use olivia_secp256k1::fun::{marker::*, Point, XOnly};
use std::{convert::TryInto, str::FromStr};

use super::{randomize::Randomize, BetArgs, Either};

pub type OfferId = XOnly;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct SignedInput {
    pub outpoint: bdk::bitcoin::OutPoint,
    pub witness: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct Payload {
    pub inputs: Vec<SignedInput>,
    pub change: Option<Change>,
    pub choose_right: bool,
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
    pub value: Amount,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Offer {
    pub inputs: Vec<SignedInput>,
    pub change: Option<Change>,
    pub public_key: Point<EvenY>,
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

impl Offer {
    pub fn encrypt(self, cipher: &mut impl StreamCipher) -> EncryptedOffer {
        let payload = Payload {
            inputs: self.inputs,
            change: self.change,
            choose_right: self.choose_right,
            value: self.value,
        };
        let mut ciphertext = crate::encode::serialize(&payload);
        cipher.apply_keystream(&mut ciphertext);
        EncryptedOffer {
            public_key: self.public_key,
            ciphertext,
        }
    }

    pub fn id(&self) -> OfferId {
        self.public_key.to_xonly()
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EncryptedOffer {
    pub public_key: Point<EvenY>,
    pub ciphertext: Vec<u8>,
}
impl EncryptedOffer {
    pub fn to_string(&self) -> String {
        crate::encode::serialize_base2048(self)
    }

    pub fn decrypt(self, cipher: &mut impl StreamCipher) -> anyhow::Result<Offer> {
        let mut plaintext = self.ciphertext;
        cipher.apply_keystream(&mut plaintext);
        let payload = crate::encode::deserialize::<Payload>(&plaintext)?;
        Ok(Offer {
            inputs: payload.inputs,
            change: payload.change,
            public_key: self.public_key,
            choose_right: payload.choose_right,
            value: payload.value,
        })
    }
}

impl FromStr for EncryptedOffer {
    type Err = crate::encode::DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        crate::encode::deserialize_base2048(s)
    }
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
    ) -> anyhow::Result<(Bet, Offer, impl StreamCipher)> {
        let remote_public_key = &proposal.public_key;
        let event_id = &oracle_event.event.id;
        if !event_id.is_binary() {
            return Err(anyhow!(
                "Cannot make a bet on {} since it isn't binary",
                event_id
            ));
        }

        let anticipated_attestations = oracle_event
            .anticipate_attestations(&oracle_info.oracle_keys.attestation_key, 0)[..2]
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
                .outpoint_to_psbt_input(*proposal_input)
                .context("Failed to find proposal input")?;
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
            let change_script = proposal.change_script.ok_or(anyhow!(
                "proposal had excess coins but did not provide change address"
            ))?;
            builder.add_recipient(change_script.into(), proposal_excess);
        }

        let (mut psbt, _tx_details) = builder
            .finish()
            .context("Unable to create offer transaction")?;

        let is_final = self
            .wallet
            .sign(&mut psbt, SignOptions::default())
            .context("Unable to sign offer transaction")?;
        assert!(
            !is_final,
            "we haven't got the other party's signature so it can't be final here"
        );

        let (vout, txout) = psbt
            .global
            .unsigned_tx
            .output
            .iter()
            .enumerate()
            .find(|(_i, txout)| &txout.script_pubkey == &output_script)
            .expect("The output must be in there");

        let joint_output_value = Amount::from_sat(txout.value);
        let local_value = joint_output_value - proposal.value;

        // the inputs we own have witnesses
        let my_input_indexes = psbt
            .inputs
            .iter()
            .enumerate()
            .filter_map(|(i, input)| input.final_script_witness.as_ref().map(|_| i))
            .collect::<Vec<_>>();

        let signed_inputs: Vec<SignedInput> = psbt
            .inputs
            .iter()
            .zip(psbt.global.unsigned_tx.input.iter())
            .filter_map(|(input, txin)| {
                input
                    .final_script_witness
                    .clone()
                    .map(|witness| -> SignedInput {
                        SignedInput {
                            outpoint: txin.previous_output,
                            witness,
                        }
                    })
            })
            .collect();

        let tx = psbt.extract_tx();
        let mut change = None;

        for output in &tx.output {
            if self.wallet.is_mine(&output.script_pubkey)? {
                change = Some(Change::new(output.value, output.script_pubkey.clone()));
            }
        }

        let offer = Offer {
            public_key: local_keypair.public_key,
            change,
            inputs: signed_inputs,
            choose_right,
            value: local_value,
        };
        let bet = Bet {
            tx,
            my_input_indexes,
            vout: vout as u32,
            joint_output: joint_output.clone(),
            oracle_id: oracle_info.id,
            oracle_event,
            local_value,
            joint_output_value,
            i_chose_right: choose_right,
        };

        Ok((bet, offer, cipher))
    }

    pub fn save_and_encrypt_offer(
        &self,
        bet: Bet,
        offer: Offer,
        mut cipher: impl StreamCipher,
    ) -> anyhow::Result<(BetId, EncryptedOffer)> {
        let bet_id = self.bet_db.insert_bet(BetState::Offered { bet })?;
        let encrypted_offer = offer.encrypt(&mut cipher);
        Ok((bet_id, encrypted_offer))
    }
}
