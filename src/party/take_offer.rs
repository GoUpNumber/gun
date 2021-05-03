use crate::{
    bet_database::{BetId, BetState},
    bet::Bet,
    OracleInfo,
};
use anyhow::{anyhow, Context};
use bdk::{
    bitcoin::{util::psbt, Amount, OutPoint, Script, Transaction},
    blockchain::Blockchain,
    database::BatchDatabase,
    wallet::tx_builder::TxOrdering,
};
use chacha20::ChaCha20Rng;
use miniscript::DescriptorTrait;
use std::convert::TryInto;

use super::{
    randomize::Randomize, Either, EncryptedOffer, JointOutput, LocalProposal, Offer, Party,
    Proposal,
};

pub struct DecryptedOffer {
    pub offer: Offer,
    pub rng: ChaCha20Rng,
}

pub struct ValidatedOffer {
    pub bet_id: BetId,
    pub bet: Bet,
    pub tx: Transaction
}

impl<B: Blockchain, D: BatchDatabase> Party<B, D> {
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
                let (mut cipher, rng) =
                    crate::ecdh::ecdh(&local_proposal.keypair, &encrypted_offer.public_key);
                let offer = encrypted_offer.decrypt(&mut cipher)?;
                Ok(DecryptedOffer { offer, rng })
            }
            _ => Err(anyhow!("Offer has been taken for this proposal already")),
        }
    }

    async fn lookup_offer_inputs(
        &self,
        offer: &Offer,
    ) -> anyhow::Result<(Vec<psbt::Input>, Amount)> {
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

        Ok((psbt_inputs,
            Amount::from_sat(offer_value)))
    }

    pub async fn decrypt_and_validate_offer(
        &self,
        bet_id: BetId,
        encrypted_offer: EncryptedOffer,
    ) -> anyhow::Result<ValidatedOffer> {
        let decrypted_offer = self.decrypt_offer(bet_id, encrypted_offer)?;
        let (psbt_inputs, offer_value) = self.lookup_offer_inputs(&decrypted_offer.offer).await?;
        let DecryptedOffer { offer, mut rng } = decrypted_offer;
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
        let oracle_id = &proposal.oracle;

        let oracle_info = self
            .bet_db
            .get_entity::<OracleInfo>(oracle_id.clone())?
            .ok_or(anyhow!("Oracle {} isn't in the database", oracle_id))?;

        let anticipated_attestations = oracle_event
            .anticipate_attestations(&oracle_info.oracle_keys.attestation_key, 0)
            .try_into()
            .map_err(|_| anyhow!("wrong number of attestations"))?;
        let joint_output = JointOutput::new(
            [local_proposal.keypair.public_key, offer.public_key],
            Either::Left(local_proposal.keypair.secret_key),
            anticipated_attestations,
            offer.choose_right,
            randomize.clone(),
        );
        let joint_output_value =
            offer_value
            .checked_add(proposal.value)
            .expect("we've checked the offer value on the chain");

        let output = (
            joint_output.descriptor().script_pubkey(),
            joint_output_value,
        );

        let (tx, vout) = self.take_offer_generate_tx(
            proposal.clone(),
            offer.clone(),
            psbt_inputs,
            output,
        )?;
        let bet = Bet {
            outpoint: OutPoint {
                txid: tx.txid(),
                vout,
            },
            oracle_id: oracle_info.id.clone(),
            oracle_event: oracle_event.clone(),
            joint_output: joint_output.clone(),
            local_value: proposal.value,
            joint_output_value,
            i_chose_right: !offer.choose_right,
        };
        Ok(ValidatedOffer {
            bet_id,
            bet,
            tx
        })
    }

    pub fn take_offer(
        &self,
        ValidatedOffer {
            bet_id,
            bet,
            tx
        }: ValidatedOffer,
    ) -> anyhow::Result<Transaction> {
        self.bet_db
            .update_bet(bet_id, |bet_state, _| match bet_state {
                BetState::Proposed { .. } => Ok(BetState::Unconfirmed {
                    bet: bet.clone(),
                    funding_transaction: tx.clone(),
                    has_broadcast: false,
                }),
                _ => Ok(bet_state),
            })?;

        Ok(tx)
    }

    pub fn take_offer_generate_tx(
        &self,
        proposal: Proposal,
        offer: Offer,
        offer_psbt_inputs: Vec<psbt::Input>,
        output: (Script, Amount),
    ) -> anyhow::Result<(Transaction, u32)> {
        let mut builder = self.wallet.build_tx();

        builder
            .manually_selected_only()
            .ordering(TxOrdering::Bip69Lexicographic)
            .fee_absolute(offer.fee as u64);

        for proposal_input in proposal.payload.inputs {
            builder.add_utxo(proposal_input)?;
        }

        for (input, psbt_input) in offer.inputs.iter().zip(offer_psbt_inputs) {
            builder.add_foreign_utxo(input.outpoint, psbt_input, 4 + 1 + 73 + 33)?;
        }

        if let Some(change) = proposal.payload.change {
            builder.add_recipient(change.script().clone(), change.value());
        }

        if let Some(change) = offer.change {
            builder.add_recipient(change.script().clone(), change.value());
        }

        builder.add_recipient(output.0.clone(), output.1.as_sat());

        let (mut psbt, _tx_details) = builder.finish()?;

        let is_final = self
            .wallet
            .sign(&mut psbt, None)
            .context("Failed to sign transaction")?;

        if !is_final {
            return Err(anyhow!("Transaction was unable to be completed"));
        }

        let tx = psbt.extract_tx();
        let vout = tx
            .output
            .iter()
            .enumerate()
            .find_map(|(i, txout)| {
                if txout.script_pubkey == output.0 {
                    Some(i)
                } else {
                    None
                }
            })
            .expect("our joint outpoint will always exist");

        Ok((tx, vout as u32))
    }
}
