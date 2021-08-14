use crate::{
    bet::Bet,
    bet_database::{BetId, BetState},
    OracleInfo,
};
use anyhow::{anyhow, Context};
use bdk::{
    bitcoin::{
        util::psbt::{self, PartiallySignedTransaction as Psbt},
        Amount, Transaction,
    },
    database::BatchDatabase,
    miniscript::DescriptorTrait,
    wallet::tx_builder::TxOrdering,
    SignOptions,
};
use chacha20::ChaCha20Rng;
use std::convert::TryInto;

use super::{
    randomize::Randomize, Either, EncryptedOffer, JointOutput, LocalProposal, Offer, Party,
};

pub struct DecryptedOffer {
    pub offer: Offer,
    pub rng: ChaCha20Rng,
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

impl<D: BatchDatabase> Party<bdk::blockchain::EsploraBlockchain, D> {
    pub fn decrypt_offer(
        &self,
        bet_id: BetId,
        encrypted_offer: EncryptedOffer,
    ) -> anyhow::Result<DecryptedOffer> {
        let local_proposal = self
            .bet_db
            .get_entity(bet_id)?
            .ok_or(anyhow!("Proposal does not exist"))?;

        match local_proposal {
            BetState::Proposed { local_proposal } => {
                let keypair = self.keychain.get_key_for_proposal(&local_proposal.proposal);
                let (mut cipher, rng) = crate::ecdh::ecdh(&keypair, &encrypted_offer.public_key);
                let offer = encrypted_offer.decrypt(&mut cipher)?;
                Ok(DecryptedOffer { offer, rng })
            }
            _ => Err(anyhow!("Offer has been taken for this proposal already")),
        }
    }

    fn lookup_offer_inputs(&self, offer: &Offer) -> anyhow::Result<(Vec<psbt::Input>, Amount)> {
        let mut psbt_inputs = vec![];
        let mut input_value = 0;
        for input in &offer.inputs {
            let mut psbt_input = self
                .outpoint_to_psbt_input(input.outpoint)
                .context("Failed to find proposal input")?;
            input_value += psbt_input.witness_utxo.as_ref().unwrap().value;
            psbt_input.final_script_witness = Some(input.witness.encode());
            psbt_inputs.push(psbt_input);
        }

        Ok((psbt_inputs, Amount::from_sat(input_value)))
    }

    pub fn decrypt_and_validate_offer(
        &self,
        bet_id: BetId,
        encrypted_offer: EncryptedOffer,
    ) -> anyhow::Result<ValidatedOffer> {
        let DecryptedOffer { offer, mut rng } = self.decrypt_offer(bet_id, encrypted_offer)?;
        let (offer_psbt_inputs, offer_input_value) = self.lookup_offer_inputs(&offer)?;

        let randomize = Randomize::new(&mut rng);

        let bet_state = self
            .bet_db
            .get_entity::<BetState>(bet_id)?
            .ok_or(anyhow!("Bet {} doesn't exist"))?;
        let local_proposal = match bet_state {
            BetState::Proposed { local_proposal } => local_proposal,
            _ => return Err(anyhow!("was not in proposed state")),
        };

        let LocalProposal {
            oracle_event,
            proposal,
            ..
        } = local_proposal;

        let keypair = self.keychain.get_key_for_proposal(&proposal);
        let oracle_id = &proposal.oracle;

        let oracle_info = self
            .bet_db
            .get_entity::<OracleInfo>(oracle_id.clone())?
            .ok_or(anyhow!("Oracle {} isn't in the database", oracle_id))?;

        let anticipated_attestations = oracle_event
            .anticipate_attestations_olivia_v1(
                &oracle_info
                    .oracle_keys
                    .olivia_v1
                    .expect("since we already proposed must have olivia-v1"),
                0,
            )
            .expect("since we already proposed the bet it must have olivia-v1")
            .try_into()
            .map_err(|_| anyhow!("wrong number of attestations"))?;

        let joint_output = JointOutput::new(
            [keypair.public_key, offer.public_key],
            Either::Left(keypair.secret_key),
            anticipated_attestations,
            offer.choose_right,
            randomize.clone(),
        );
        let joint_output_value = offer
            .value
            .checked_add(proposal.value)
            .expect("we've checked the offer value on the chain");
        let joint_output_script_pubkey = joint_output.descriptor().script_pubkey();

        let mut builder = self.wallet.build_tx();

        builder
            .manually_selected_only()
            .ordering(TxOrdering::Bip69Lexicographic)
            .enable_rbf();

        for proposal_input in &proposal.inputs {
            builder.add_utxo(*proposal_input)?;
        }

        for (input, psbt_input) in offer.inputs.iter().zip(offer_psbt_inputs) {
            builder.add_foreign_utxo(input.outpoint, psbt_input, 4 + 1 + 73 + 33)?;
        }

        if let Some(change) = local_proposal.change {
            builder.add_recipient(change.script().clone(), change.value().as_sat());
        }

        let mut absolute_fee = offer_input_value
            .checked_sub(offer.value)
            .ok_or(anyhow!("offer value is more than input value"))?;

        if let Some(change) = offer.change {
            absolute_fee = absolute_fee
                .checked_sub(change.value())
                .ok_or(anyhow!("too much change requested"))?;
            builder.add_recipient(change.script().clone(), change.value().as_sat());
        }

        builder
            .add_recipient(
                joint_output_script_pubkey.clone(),
                joint_output_value.as_sat(),
            )
            .fee_absolute(absolute_fee.as_sat());

        let (mut psbt, _tx_details) = builder.finish()?;

        let is_final = self
            .wallet
            .sign(&mut psbt, SignOptions::default())
            .context("Failed to sign transaction")?;

        if !is_final {
            return Err(anyhow!("Transaction is incomplete after signing it"));
        }

        let vout = psbt
            .global
            .unsigned_tx
            .output
            .iter()
            .enumerate()
            .find_map(|(i, txout)| {
                if txout.script_pubkey == joint_output_script_pubkey {
                    Some(i)
                } else {
                    None
                }
            })
            .expect("our joint outpoint will always exist") as u32;

        let my_input_indexes = proposal
            .inputs
            .iter()
            .map(|input| {
                psbt.global
                    .unsigned_tx
                    .input
                    .iter()
                    .enumerate()
                    .find(|(_, txin)| txin.previous_output == *input)
                    .unwrap()
                    .0
            })
            .collect();

        let bet = Bet {
            psbt,
            my_input_indexes,
            vout,
            oracle_id: oracle_info.id.clone(),
            oracle_event: oracle_event.clone(),
            joint_output: joint_output.clone(),
            local_value: proposal.value,
            joint_output_value,
            i_chose_right: !offer.choose_right,
            tags: local_proposal.tags,
        };

        Ok(ValidatedOffer { bet_id, bet })
    }

    pub fn set_offer_taken(
        &self,
        ValidatedOffer { bet_id, bet, .. }: ValidatedOffer,
    ) -> anyhow::Result<Psbt> {
        self.bet_db
            .update_bets(&[bet_id], |bet_state, _, _| match bet_state {
                BetState::Proposed { .. } => Ok(BetState::Unconfirmed { bet: bet.clone() }),
                _ => Ok(bet_state),
            })?;

        Ok(bet.psbt)
    }
}
