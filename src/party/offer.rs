use std::convert::TryInto;

use crate::{
    bet_database::{Bet, BetDatabase, BetId, BetState},
    change::Change,
    keychain::KeyPair,
    party::{proposal::Proposal, JointOutput, Party},
};
use anyhow::{anyhow, Context};
use bdk::{
    bitcoin::{
        util::{amount, psbt::PartiallySignedTransaction as PSBT},
        Amount, Script, Transaction, Txid,
    },
    blockchain::Blockchain,
    database::BatchDatabase,
    descriptor::ExtendedDescriptor,
    wallet::{tx_builder::TxOrdering, ForeignUtxo},
    TxBuilder, Wallet,
};
type DefaultCoinSelectionAlgorithm = bdk::wallet::coin_selection::LargestFirstCoinSelection;

use chacha20::stream_cipher::StreamCipher;
use olivia_core::{OracleEvent, OracleInfo};
use olivia_secp256k1::{
    fun::{marker::*, Point, XOnly},
    Secp256k1,
};

use super::Either;

pub type OfferId = XOnly;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct SignedInput {
    pub outpoint: bdk::bitcoin::OutPoint,
    pub witness: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct Payload {
    #[serde(with = "amount::serde::as_sat")]
    pub value: Amount,
    pub inputs: Vec<SignedInput>,
    pub change: Option<Change>,
    pub choose_right: bool,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Offer {
    #[serde(with = "amount::serde::as_sat")]
    pub value: Amount,
    pub inputs: Vec<SignedInput>,
    pub change: Option<Change>,
    pub public_key: Point<EvenY>,
    pub choose_right: bool,
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
            value: self.value,
            inputs: self.inputs,
            change: self.change,
            choose_right: self.choose_right,
        };
        let mut ciphertext = crate::encode::serialize(&payload);
        cipher.encrypt(&mut ciphertext);
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
        cipher.decrypt(&mut plaintext);
        let payload = crate::encode::deserialize::<Payload>(&plaintext)?;
        Ok(Offer {
            value: payload.value,
            inputs: payload.inputs,
            change: payload.change,
            public_key: self.public_key,
            choose_right: payload.choose_right,
        })
    }
}

impl<B: Blockchain, D: BatchDatabase, BD: BetDatabase> Party<B, D, BD> {
    pub async fn make_offer(
        &self,
        proposal: Proposal,
        choose_right: bool,
        local_value: Amount,
    ) -> anyhow::Result<(BetId, EncryptedOffer, JointOutput, Txid)> {
        let url = crate::reqwest::Url::parse(&format!(
            "http://{}{}",
            proposal.oracle, proposal.event_id
        ))?;
        let oracle_event = self.get_oracle_event_from_url(url).await?;
        let oracle_info = self.save_oracle_info(proposal.oracle.clone()).await?;
        self.make_offer_with_oracle_event(
            proposal,
            choose_right,
            local_value,
            oracle_event,
            oracle_info,
        )
        .await
    }

    pub async fn make_offer_with_oracle_event(
        &self,
        proposal: Proposal,
        choose_right: bool,
        local_value: Amount,
        oracle_event: OracleEvent<Secp256k1>,
        oracle_info: OracleInfo<Secp256k1>,
    ) -> anyhow::Result<(BetId, EncryptedOffer, JointOutput, Txid)> {
        let remote_public_key = &proposal.payload.public_key;
        let event_id = &oracle_event.event.id;
        if !event_id.is_binary() {
            return Err(anyhow!(
                "Cannot make a bet on {} since it isn't binary",
                event_id
            ));
        }

        let anticipated_signatures = oracle_event
            .anticipate_signatures(&oracle_info.public_key, 0)
            .try_into()
            .unwrap();

        let local_keypair = self.keychain.keypair_for_offer(&proposal);
        let (mut cipher, mut rng) = crate::ecdh::ecdh(&local_keypair, remote_public_key);

        let (offer, joint_output, txid) = self
            .generate_offer(
                proposal,
                local_value,
                anticipated_signatures,
                local_keypair,
                choose_right,
                &mut rng,
            )
            .await?;

        let bet = Bet {
            funding_txid: txid,
            vout: 0,
            joint_output: joint_output.clone(),
            oracle_info,
            oracle_event,
        };

        let bet_id = self.bets_db.insert_bet(BetState::Offered { bet })?;
        let encrypted_offer = offer.encrypt(&mut cipher);

        Ok((bet_id, encrypted_offer, joint_output, txid))
    }

    async fn generate_offer(
        &self,
        proposal: Proposal,
        local_value: Amount,
        anticipated_signatures: [Point<Jacobian, Public, Zero>; 2],
        local_keypair: KeyPair,
        choose_right: bool,
        rng: &mut chacha20::ChaCha20Rng,
    ) -> anyhow::Result<(Offer, JointOutput, Txid)> {
        let remote_public_key = proposal.payload.public_key;

        let joint_output = JointOutput::new(
            [remote_public_key, local_keypair.public_key],
            Either::Right(local_keypair.secret_key),
            anticipated_signatures,
            choose_right,
            rng,
        );

        let output_value = local_value
            .checked_add(proposal.value)
            .ok_or(anyhow!("BTC amount overflow"))?;

        let output = (
            joint_output
                .descriptor()
                .script_pubkey(self.descriptor_derp_ctx()),
            output_value,
        );

        let psbt = generate_tx(&self.wallet, &proposal, output).await?;

        let inputs: Vec<SignedInput> = psbt
            .inputs
            .iter()
            .zip(psbt.global.unsigned_tx.input.iter())
            .filter_map(|(input, txin)| {
                input
                    .final_script_witness
                    .clone()
                    .map(|witness| SignedInput {
                        outpoint: txin.previous_output,
                        witness: witness,
                    })
            })
            .collect();

        let tx = psbt.extract_tx();
        let txid = tx.txid();
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
            value: local_value,
        };

        Ok((offer, joint_output, txid))
    }
}

pub async fn generate_tx(
    wallet: &Wallet<impl Blockchain, impl BatchDatabase>,
    proposal: &Proposal,
    output: (Script, Amount),
) -> anyhow::Result<PSBT> {
    let mut builder = TxBuilder::default()
        .add_recipient(output.0, output.1.as_sat())
        .ordering(TxOrdering::Untouched);
    let mut required_input_value = proposal.value.as_sat();
    let mut input_value = 0;
    for proposal_input in &proposal.payload.inputs {
        let tx = wallet
            .client()
            .unwrap()
            .get_tx(&proposal_input.txid)
            .await?
            .ok_or(anyhow!(
                "Proposal input txid not found {}",
                proposal_input.txid
            ))?;

        let txin = tx.output[proposal_input.vout as usize].clone();
        input_value += txin.value;
        builder = builder.add_foreign_utxo(
            ForeignUtxo::from_pubkey_outpoint_onchain(*proposal_input, wallet.client().unwrap())
                .await?
                .ok_or(anyhow!("proposal input {} does not exist", proposal_input))?,
        );
    }

    if let Some(change) = &proposal.payload.change {
        builder = builder.add_recipient(change.script().clone(), change.value());
        required_input_value += change.value();
    }

    if input_value != required_input_value {
        return Err(anyhow!(
            "input value was {} but we need {}",
            input_value,
            required_input_value
        ));
    }

    let (psbt, _tx_details) = wallet
        .create_tx::<DefaultCoinSelectionAlgorithm>(builder)
        .context("Unable to create offer transaction")?;
    let (psbt, is_final) = wallet
        .sign(psbt, None)
        .context("Unable to sign offer transaction")?;
    assert!(
        !is_final,
        "we haven't got the other party's signature so it can't be final here"
    );
    Ok(psbt)
}
