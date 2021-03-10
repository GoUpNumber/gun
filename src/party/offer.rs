use crate::{
    bet_database::{Bet, BetDatabase, BetId, BetState},
    change::Change,
    keychain::KeyPair,
    party::{proposal::Proposal, JointOutput, Party},
};
use anyhow::{anyhow, Context};
use bdk::{
    bitcoin::{
        util::{psbt, psbt::PartiallySignedTransaction as PSBT},
        Amount, OutPoint, Script, Transaction, TxIn,
    },
    blockchain::Blockchain,
    database::BatchDatabase,
    descriptor::ExtendedDescriptor,
    miniscript::DescriptorTrait,
    wallet::tx_builder::TxOrdering,
};
use chacha20::cipher::StreamCipher;
use olivia_core::{OracleEvent, OracleInfo};
use olivia_secp256k1::{
    fun::{marker::*, Point, XOnly},
    Secp256k1,
};
use std::convert::TryInto;

use super::{randomize::Randomize, Either};

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
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Offer {
    pub inputs: Vec<SignedInput>,
    pub change: Option<Change>,
    pub public_key: Point<EvenY>,
    pub choose_right: bool,
    pub fee: u32,
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
        })
    }
}

impl<B: Blockchain, D: BatchDatabase, BD: BetDatabase> Party<B, D, BD> {
    pub async fn make_offer(
        &self,
        proposal: Proposal,
        choose_right: bool,
        local_value: Amount,
    ) -> anyhow::Result<(BetId, EncryptedOffer)> {
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
    ) -> anyhow::Result<(BetId, EncryptedOffer)> {
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
        let output_value = local_value
            .checked_add(proposal.value)
            .ok_or(anyhow!("BTC amount overflow"))?;

        let (offer, joint_output, outpoint) = self
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
            outpoint,
            joint_output: joint_output.clone(),
            oracle_info,
            oracle_event,
            value: output_value,
        };

        let bet_id = self.bets_db.insert_bet(BetState::Offered { bet })?;
        let encrypted_offer = offer.encrypt(&mut cipher);

        Ok((bet_id, encrypted_offer))
    }

    async fn generate_offer(
        &self,
        proposal: Proposal,
        output_value: Amount,
        anticipated_signatures: [Point<Jacobian, Public, Zero>; 2],
        local_keypair: KeyPair,
        choose_right: bool,
        rng: &mut chacha20::ChaCha20Rng,
    ) -> anyhow::Result<(Offer, JointOutput, OutPoint)> {
        let remote_public_key = proposal.payload.public_key;
        let randomize = Randomize::new(rng);

        let joint_output = JointOutput::new(
            [remote_public_key, local_keypair.public_key],
            Either::Right(local_keypair.secret_key),
            anticipated_signatures,
            choose_right,
            randomize,
        );

        let output = (joint_output.descriptor().script_pubkey(), output_value);

        let (psbt, vout, fee) = self.make_offer_generate_tx(&proposal, output).await?;

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
            fee,
        };

        Ok((offer, joint_output, OutPoint { txid, vout }))
    }

    pub async fn make_offer_generate_tx(
        &self,
        proposal: &Proposal,
        output: (Script, Amount),
    ) -> anyhow::Result<(PSBT, u32, u32)> {
        let mut builder = self.wallet.build_tx();
        builder
            .add_recipient(output.0.clone(), output.1.as_sat())
            .ordering(TxOrdering::BIP69Lexicographic);

        let mut required_input_value = proposal.value.as_sat();
        let mut input_value = 0;
        for proposal_input in &proposal.payload.inputs {
            let txout = self
                .get_txout(*proposal_input)
                .await
                .context("Failed to find proposal input")?;
            input_value += txout.value;
            let psbt_input = psbt::Input {
                witness_utxo: Some(txout),
                ..Default::default()
            };
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

        let (psbt, tx_details) = builder
            .finish()
            .context("Unable to create offer transaction")?;

        let (psbt, is_final) = self
            .wallet
            .sign(psbt, None)
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

// /// Creates a foreign UTXO by guessing the weight of the witness by the fact that it's a public
// /// key output.
// ///
// /// # Examples
// /// ```
// /// ForeignUtxo::from_
// /// ```
// #[maybe_async]
// pub fn from_onchain_(
//     outpoint: OutPoint,
//     blockchain: &impl Blockchain,
// ) -> Result<Option<Self>, Error> {
//     let tx =
//         maybe_await!(blockchain.get_tx(&outpoint.txid))?.ok_or(Error::TransactionNotFound)?;
//     let output = tx
//         .output
//         .get(outpoint.vout as usize)
//         .ok_or(Error::InvalidOutpoint(outpoint))?;
//     let script_pubkey = output.script_pubkey.clone();

//     // at the worst we assume it's a uncmopressed public key on chain.
//     let max_satisfaction_weight = if script_pubkey.is_p2pk() {
//         4 * (1 + 73)
//     } else if script_pubkey.is_p2pkh() {
//         // conservatively assume uncompressed public key
//         4 * (1 + 73 + 65)
//     } else if script_pubkey.is_v0_p2wpkh() {
//         // XXX: Technically, public keys could be uncompressed here as well, but this is would
//         // only occur if a miner was intentionally trying fool you since in BIP143 nodes will
//         // not allow uncompressed public keys in the witness
//         4 + 1 + 73 + 33
//     } else {
//         // FIXME: Add taproot here?
//         return Ok(None);
//     };

//     Ok(Some(Self {
//         value: output.value,
//         outpoint,
//         script_pubkey,
//         max_satisfaction_weight,
//     }))
// }
