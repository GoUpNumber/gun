use super::BetArgs;
use crate::{betting::*, change::Change, FeeSpec, ValueChoice};
use anyhow::{anyhow, Context};
use bdk::{
    bitcoin::Amount,
    database::BatchDatabase,
    miniscript::DescriptorTrait,
    wallet::{coin_selection::LargestFirstCoinSelection, tx_builder::TxOrdering, IsDust},
    SignOptions,
};
use chacha20::cipher::StreamCipher;
use std::convert::TryInto;

impl<D: BatchDatabase> Party<bdk::blockchain::EsploraBlockchain, D> {
    pub fn generate_offer_with_oracle_event(
        &self,
        proposal: Proposal,
        choose_right: bool,
        oracle_event: OracleEvent,
        oracle_info: OracleInfo,
        args: BetArgs<'_, '_>,
        fee_spec: FeeSpec,
    ) -> anyhow::Result<(Bet, Point<EvenY>, impl StreamCipher)> {
        let remote_public_key = &proposal.public_key;
        let event_id = &oracle_event.event.id;
        if event_id.n_outcomes() != 2 {
            return Err(anyhow!(
                "Cannot make a bet on {} since it isn't binary",
                event_id
            ));
        }

        let anticipated_attestations = oracle_event
            .anticipate_attestations_olivia_v1(&oracle_info.oracle_keys.olivia_v1.ok_or(anyhow!("Oracle '{}' does not support olivia_v1", oracle_info.id))?, 0)
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

        let mut builder = self
            .wallet
            .build_tx()
            .coin_selection(LargestFirstCoinSelection);
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

        let (psbt, _tx_details) = builder
            .finish()
            .context("Unable to create offer transaction")?;

        // the inputs we own have witnesses
        let my_input_indexes = psbt
            .unsigned_tx
            .input
            .iter()
            .enumerate()
            .filter(|(_, input)| !proposal.inputs.contains(&input.previous_output))
            .map(|(i, _)| i as u32)
            .collect::<Vec<_>>();

        let (vout, txout) = psbt
            .unsigned_tx
            .output
            .iter()
            .enumerate()
            .find(|(_i, txout)| txout.script_pubkey == output_script)
            .expect("The bet output must be in there");

        let joint_output_value = Amount::from_sat(txout.value);
        let local_value = joint_output_value - proposal.value;

        let bet = Bet {
            psbt,
            my_input_indexes,
            vout: vout as u32,
            joint_output,
            oracle_id: oracle_info.id,
            oracle_event,
            local_value,
            joint_output_value,
            i_chose_right: choose_right,
            tags: args.tags,
        };

        Ok((bet, local_keypair.public_key, cipher))
    }

    pub fn sign_save_and_encrypt_offer(
        &self,
        mut bet: Bet,
        message: Option<String>,
        local_public_key: Point<EvenY>,
        cipher: &mut impl StreamCipher,
    ) -> anyhow::Result<(BetId, Ciphertext, Offer)> {
        let is_final = self
            .wallet
            .sign(&mut bet.psbt, SignOptions::default())
            .context("Unable to sign offer transaction")?;

        if is_final {
            // the only reason it would be final is that the wallet is doing a bet with itself
            return Err(anyhow!("sorry you can't do bets with yourself yet!"));
        }

        let signed_inputs: Vec<SignedInput> = bet
            .my_input_indexes
            .iter()
            .cloned()
            .map(|i| {
                let txin = &bet.psbt.unsigned_tx.input[i as usize];
                let psbt_input = &bet.psbt.inputs[i as usize];
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

        for output in &bet.psbt.unsigned_tx.output {
            if self.wallet.is_mine(&output.script_pubkey)? {
                change = Some(Change::new(output.value, output.script_pubkey.clone()));
            }
        }

        let offer = Offer {
            change,
            inputs: signed_inputs,
            choose_right: bet.i_chose_right,
            value: bet.local_value,
        };

        let encrypted_offer = Ciphertext::create(
            local_public_key,
            cipher,
            Plaintext::Offerv1 {
                offer: offer.clone(),
                message,
            },
        );
        let bet_id = self.bet_db.insert_bet(BetState::Offered {
            bet: OfferedBet(bet),
            encrypted_offer: encrypted_offer.clone(),
        })?;
        Ok((bet_id, encrypted_offer, offer))
    }
}
