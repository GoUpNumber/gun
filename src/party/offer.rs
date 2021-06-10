use crate::{
    bet::Bet,
    bet_database::{BetId, BetState},
    change::Change,
    keychain::KeyPair,
    party::{proposal::Proposal, JointOutput, Party},
};
use anyhow::{anyhow, Context};
use bdk::{
    bitcoin::{
        self, util::psbt::PartiallySignedTransaction as PSBT, Amount, Script, Transaction, TxIn,
    },
    database::BatchDatabase,
    descriptor::ExtendedDescriptor,
    miniscript::DescriptorTrait,
    wallet::tx_builder::TxOrdering,
    SignOptions,
};
use chacha20::cipher::StreamCipher;
use olivia_core::{OracleEvent, OracleInfo};
use olivia_secp256k1::{
    fun::{marker::*, Point, XOnly},
    Secp256k1,
};
use std::{convert::TryInto, str::FromStr};

use super::{randomize::Randomize, BetArgs, Either};

pub type OfferId = XOnly;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct SignedInput {
    pub outpoint: bdk::bitcoin::OutPoint,
    pub witness: Vec<Vec<u8>>,
}

impl SignedInput {
    fn to_txin(&self) -> TxIn {
        TxIn {
            previous_output: self.outpoint,
            witness: self.witness.clone(),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct Payload {
    pub inputs: Vec<SignedInput>,
    pub change: Option<Change>,
    pub choose_right: bool,
    pub fee: u32,
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
    pub value: Amount,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Offer {
    pub inputs: Vec<SignedInput>,
    pub change: Option<Change>,
    pub public_key: Point<EvenY>,
    pub choose_right: bool,
    pub fee: u32,
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
            fee: self.fee,
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

    pub fn fee_rate(&self) -> bdk::FeeRate {
        let template_tx = Transaction {
            input: self.inputs.iter().map(|input| input.to_txin()).collect(),
            // TODO: put dummy txout here,
            output: vec![],
            lock_time: 0,
            version: 0,
        };
        bdk::FeeRate::from_sat_per_vb((self.fee as f32) / (template_tx.get_weight() as f32 / 4.0))
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
            fee: payload.fee,
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
    pub async fn generate_offer(
        &self,
        proposal: Proposal,
        choose_right: bool,
        args: BetArgs<'_, '_>,
    ) -> anyhow::Result<(Bet, Offer, impl StreamCipher)> {
        let url = crate::reqwest::Url::parse(&format!(
            "http://{}{}",
            proposal.oracle, proposal.event_id
        ))?;
        let oracle_event = self.get_oracle_event_from_url(url).await?;
        let oracle_info = self.save_oracle_info(proposal.oracle.clone()).await?;
        self.generate_offer_with_oracle_event(
            proposal,
            choose_right,
            oracle_event,
            oracle_info,
            args,
        )
        .await
    }

    pub async fn generate_offer_with_oracle_event(
        &self,
        proposal: Proposal,
        choose_right: bool,
        oracle_event: OracleEvent<Secp256k1>,
        oracle_info: OracleInfo<Secp256k1>,
        args: BetArgs<'_, '_>,
    ) -> anyhow::Result<(Bet, Offer, impl StreamCipher)> {
        let remote_public_key = &proposal.payload.public_key;
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

        let remote_public_key = proposal.payload.public_key;
        let randomize = Randomize::new(&mut rng);

        let joint_output = JointOutput::new(
            [remote_public_key, local_keypair.public_key],
            Either::Right(local_keypair.secret_key),
            anticipated_attestations,
            choose_right,
            randomize,
        );

        let local_value = args.value;
        let joint_output_value = local_value
            .checked_add(proposal.value)
            .ok_or(anyhow!("BTC amount overflow"))?;

        let output = (
            joint_output.descriptor().script_pubkey(),
            joint_output_value,
        );

        let (psbt, vout, fee) = self.make_offer_generate_tx(&proposal, output, args).await?;

        // the inputs we own have witnesses
        let my_input_indexes = psbt
            .inputs
            .iter()
            .enumerate()
            .filter_map(|(i, input)| input.final_script_witness.as_ref().map(|_| i))
            .collect::<Vec<_>>();

        let inputs: Vec<SignedInput> = psbt
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
            inputs,
            choose_right,
            fee,
            value: local_value,
        };
        let bet = Bet {
            tx,
            my_input_indexes,
            vout,
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

    async fn make_offer_generate_tx(
        &self,
        proposal: &Proposal,
        output: (Script, Amount),
        args: BetArgs<'_, '_>,
    ) -> anyhow::Result<(PSBT, u32, u32)> {
        let mut builder = self.wallet.build_tx();
        builder
            .add_recipient(output.0.clone(), output.1.as_sat())
            .ordering(TxOrdering::Bip69Lexicographic);

        args.apply_args(self.bet_db(), &mut builder)?;

        let mut required_input_value = proposal.value.as_sat();
        let mut input_value = 0;
        for proposal_input in &proposal.payload.inputs {
            let psbt_input = self
                .outpoint_to_psbt_input(*proposal_input)
                .await
                .context("Failed to find proposal input")?;
            input_value += psbt_input.witness_utxo.as_ref().unwrap().value;
            builder.add_foreign_utxo(
                *proposal_input,
                psbt_input,
                // p2wpkh wieght
                4 + 1 + 73 + 33,
            )?;
        }

        if let Some(change) = &proposal.payload.change {
            builder.add_recipient(change.script().clone(), change.value());
            required_input_value += change.value();
        }

        if input_value != required_input_value {
            return Err(anyhow!(
                "input value was {} but we need {}",
                input_value,
                required_input_value
            ));
        }

        let (mut psbt, tx_details) = builder
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
        let (vout, _) = psbt
            .global
            .unsigned_tx
            .output
            .iter()
            .enumerate()
            .find(|(_i, txout)| txout.script_pubkey == output.0)
            .expect("The output must be in there");
        Ok((psbt, vout as u32, tx_details.fees as u32))
    }
}
