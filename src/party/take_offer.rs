use crate::bet_database::{BetDatabase, BetId, BetState};
use anyhow::{anyhow, Context};
use bdk::{
    bitcoin::{
        util::{psbt, psbt::PartiallySignedTransaction as PSBT},
        Amount, Script, Transaction, TxIn, TxOut,
    },
    blockchain::Blockchain,
    database::BatchDatabase,
};
use chacha20::ChaCha20Rng;
use std::convert::TryInto;

use super::{Either, EncryptedOffer, JointOutput, LocalProposal, Offer, Party, Proposal};

#[derive(Debug, Clone)]
pub struct DecryptedOffer {
    pub offer: Offer,
    pub rng: ChaCha20Rng,
}

impl<B: Blockchain, D: BatchDatabase, BD: BetDatabase> Party<B, D, BD> {
    pub fn decrypt_offer(
        &self,
        bet_id: BetId,
        encrypted_offer: EncryptedOffer,
    ) -> anyhow::Result<(LocalProposal, DecryptedOffer)> {
        let local_proposal = self
            .bets_db
            .get_bet(bet_id)?
            .ok_or(anyhow!("Proposal does not exist"))?;

        match local_proposal {
            BetState::Proposed { local_proposal } => {
                let (mut cipher, rng) =
                    crate::ecdh::ecdh(&local_proposal.keypair, &encrypted_offer.public_key);
                let offer = encrypted_offer.decrypt(&mut cipher)?;
                Ok((local_proposal, DecryptedOffer { offer, rng }))
            }
            _ => Err(anyhow!("Offer has been taken for this proposal already")),
        }
    }

    pub async fn take_offer(
        &self,
        bet_id: BetId,
        local_proposal: LocalProposal,
        offer: DecryptedOffer,
    ) -> anyhow::Result<JointOutput> {
        let DecryptedOffer { offer, mut rng } = offer;
        let LocalProposal {
            oracle_event,
            oracle_info,
            proposal,
            psbt_inputs,
            ..
        } = local_proposal;

        let anticipated_signatures = oracle_event
            .anticipate_signatures(&oracle_info.public_key, 0)
            .try_into()
            .map_err(|_| anyhow!("wrong number of signatures"))?;

        let joint_output = JointOutput::new(
            [local_proposal.keypair.public_key, offer.public_key],
            Either::Left(local_proposal.keypair.secret_key),
            anticipated_signatures,
            offer.choose_right,
            &mut rng,
        );

        let output_value = proposal
            .value
            .checked_add(offer.value)
            .ok_or(anyhow!("BTC value overflow"))?;

        let output = (
            joint_output
                .descriptor()
                .script_pubkey(self.descriptor_derp_ctx()),
            output_value,
        );

        let tx = self
            .take_offer_generate_tx(proposal.clone(), psbt_inputs, offer.clone(), output)
            .await?;

        self.bets_db
            .take_offer(bet_id, tx.clone(), 0, joint_output.clone())?;

        self.wallet
            .broadcast(tx)
            .await
            .context("Failed to broadcast funding transaction")?;

        Ok(joint_output)
    }

    pub async fn take_offer_generate_tx(
        &self,
        proposal: Proposal,
        my_inputs: Vec<psbt::Input>,
        offer: Offer,
        output: (Script, Amount),
    ) -> anyhow::Result<Transaction> {
        let proposal_inputs = proposal.payload.inputs;
        let offer_inputs = offer.inputs.iter().map(|i| i.outpoint.clone());
        let mut input_value = 0;
        let mut output_value = output.1.as_sat();
        let mut real_offer_value = 0;

        for input in &offer.inputs {
            let txout = self
                .get_txout(input.outpoint)
                .await
                .context("Failed to find input for offer")?;
            real_offer_value += txout.value;
            input_value += txout.value;
        }

        for input in &my_inputs {
            input_value += input
                .witness_utxo
                .as_ref()
                .expect("we only make proposals with segwit inputs")
                .value;
        }

        let mut tx = Transaction {
            input: proposal_inputs
                .clone()
                .into_iter()
                .chain(offer_inputs.clone().into_iter())
                .map(|previous_output| TxIn {
                    previous_output,
                    ..Default::default()
                })
                .collect(),
            version: 1,
            lock_time: 0,
            output: vec![TxOut {
                script_pubkey: output.0,
                value: output.1.as_sat(),
            }],
        };

        if let Some(change) = proposal.payload.change {
            output_value = output_value
                .checked_add(change.value())
                .ok_or(anyhow!("Proposal change value is absurdly high"))?;
            tx.output.push(TxOut {
                script_pubkey: change.script().clone(),
                value: change.value(),
            });
        }

        if let Some(change) = offer.change {
            output_value = output_value
                .checked_add(change.value())
                .ok_or(anyhow!("Offer change value is absurdly large"))?;
            real_offer_value = real_offer_value
                .checked_sub(change.value())
                .ok_or(anyhow!("Offer change value is incoherently large"))?;
            tx.output.push(TxOut {
                script_pubkey: change.script().clone(),
                value: change.value(),
            });
        }

        let mut psbt = PSBT::from_unsigned_tx(tx)?;
        let mut input_idx = 0;

        for my_input in my_inputs {
            psbt.inputs[input_idx] = my_input;
            input_idx += 1;
        }

        for offer_input in offer.inputs.into_iter() {
            psbt.inputs[input_idx].final_script_witness = Some(offer_input.witness);
            input_idx += 1;
        }

        let real_fee = input_value.checked_sub(output_value).ok_or(anyhow!(
            "Value provided by inputs ({}) was less than output amount ({})",
            input_value,
            output_value
        ))?;

        if real_fee < offer.fee.into() {
            return Err(anyhow!(
                "The offer pays lower fee ({}) than stated ({})",
                real_fee,
                offer.fee
            ));
        }

        real_offer_value = real_offer_value
            .checked_sub(real_fee)
            .ok_or(anyhow!("Fee isn't covered by offered inputs"))?;

        if real_offer_value != offer.value.as_sat() {
            return Err(anyhow!(
                "The offer's inputs do ({}) not sum up to the value in the offer ({})",
                real_offer_value,
                offer.value
            ));
        }

        let (psbt, is_final) = self
            .wallet
            .sign(psbt, None)
            .context("Failed to sign transaction")?;

        if !is_final {
            return Err(anyhow!("Transaction was unable to be completed"));
        }

        let tx = psbt.extract_tx();
        Ok(tx)
    }
}
