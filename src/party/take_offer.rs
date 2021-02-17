use crate::bet_database::{BetDatabase, BetId, BetState};
use anyhow::{anyhow, Context};
use bdk::{
    bitcoin::{util::psbt, Amount, Script, Transaction},
    blockchain::Blockchain,
    database::BatchDatabase,
    wallet::tx_builder::TxOrdering,
};
use chacha20::ChaCha20Rng;
use miniscript::DescriptorTrait;
use std::convert::TryInto;

use super::{Either, EncryptedOffer, JointOutput, LocalProposal, Offer, Party, Proposal};

#[derive(Debug, Clone)]
pub struct DecryptedOffer {
    pub offer: Offer,
    pub rng: ChaCha20Rng,
}

#[derive(Debug, Clone)]
pub struct OfferInputs {
    pub offer_value: Amount,
    pub psbt_inputs: Vec<psbt::Input>,
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

    pub async fn lookup_offer_inputs(&self, offer: &Offer) -> anyhow::Result<OfferInputs> {
        let mut psbt_inputs = vec![];
        let mut input_value = 0;
        for input in &offer.inputs {
            let txout = self
                .get_txout(input.outpoint)
                .await
                .context("Failed to find input for offer")?;
            input_value += txout.value;
            let psbt_input = psbt::Input {
                witness_utxo: Some(txout),
                final_script_witness: Some(input.witness.clone()),
                ..Default::default()
            };
            psbt_inputs.push(psbt_input);
        }

        let offer_value = input_value
            .checked_sub(offer.change.as_ref().map(|c| c.value()).unwrap_or(0))
            .ok_or(anyhow!("offer change is absurdly high"))?
            .checked_sub(offer.fee as u64)
            .ok_or(anyhow!("fee is absurdly high"))?;

        Ok(OfferInputs {
            psbt_inputs,
            offer_value: Amount::from_sat(offer_value),
        })
    }

    pub async fn take_offer(
        &self,
        bet_id: BetId,
        local_proposal: LocalProposal,
        offer: DecryptedOffer,
        offer_inputs: OfferInputs,
    ) -> anyhow::Result<JointOutput> {
        let DecryptedOffer { offer, mut rng } = offer;
        let LocalProposal {
            oracle_event,
            oracle_info,
            proposal,
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

        let output = (
            joint_output.descriptor().script_pubkey(),
            offer_inputs
                .offer_value
                .checked_add(proposal.value)
                .expect("we've checked the offer value on the chain"),
        );

        let tx = self
            .take_offer_generate_tx(proposal.clone(), offer, offer_inputs, output)
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
        offer: Offer,
        offer_inputs: OfferInputs,
        output: (Script, Amount),
    ) -> anyhow::Result<Transaction> {
        let mut builder = self.wallet.build_tx();

        builder
            .manually_selected_only()
            .ordering(TxOrdering::BIP69Lexicographic)
            .fee_absolute(offer.fee as u64);

        for proposal_input in proposal.payload.inputs {
            builder.add_utxo(proposal_input)?;
        }

        for (input, psbt_input) in offer.inputs.iter().zip(offer_inputs.psbt_inputs) {
            builder.add_foreign_utxo(input.outpoint, psbt_input, 4 + 1 + 73 + 33)?;
        }

        if let Some(change) = proposal.payload.change {
            builder.add_recipient(change.script().clone(), change.value());
        }

        if let Some(change) = offer.change {
            builder.add_recipient(change.script().clone(), change.value());
        }

        builder.add_recipient(output.0, output.1.as_sat());

        let (psbt, _tx_details) = builder.finish()?;

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
