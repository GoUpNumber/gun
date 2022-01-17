use crate::{betting::*, change::Change, ValueChoice};
use anyhow::{anyhow, Context};
use bdk::{
    bitcoin::{Amount, Script},
    database::BatchDatabase,
    FeeRate,
};
use olivia_core::{OracleEvent, OracleId};
use olivia_secp256k1::Secp256k1;

use super::BetArgs;

impl<D: BatchDatabase> Party<bdk::blockchain::EsploraBlockchain, D> {
    pub fn make_proposal(
        &self,
        oracle_id: OracleId,
        oracle_event: OracleEvent<Secp256k1>,
        args: BetArgs,
    ) -> anyhow::Result<LocalProposal> {
        let event_id = &oracle_event.event.id;
        if event_id.n_outcomes() != 2 {
            return Err(anyhow!(
                "Cannot make a bet on {} since it isn't binary",
                event_id
            ));
        }

        let mut builder = self.wallet.build_tx();
        // we use a 0 feerate because the offerer will pay the fee
        builder.fee_rate(FeeRate::from_sat_per_vb(0.0));

        match args.value {
            ValueChoice::All => builder.drain_wallet().drain_to(Script::default()),
            ValueChoice::Amount(amount) => {
                builder.add_recipient(Script::default(), amount.as_sat())
            }
        };

        args.apply_args(self.bet_db(), &mut builder)?;

        let (psbt, txdetails) = builder
            .finish()
            .context("Failed to gather proposal outputs")?;

        debug_assert!(
            // The tx fee *should* be nothing but it's possible the bet value is so close to the
            // UTXO value that it gets added to fee rather than creating a dust output.
            txdetails.fee.unwrap() < 546,
            "the fee should only be there if it's dust"
        );

        let outputs = &psbt.unsigned_tx.output;
        let tx_inputs = psbt
            .unsigned_tx
            .input
            .iter()
            .map(|txin| txin.previous_output)
            .collect();

        let value = Amount::from_sat(
            outputs
                .iter()
                .find(|o| o.script_pubkey == Script::default())
                .unwrap()
                .value,
        );

        let change = if outputs.len() > 1 {
            if outputs.len() != 2 {
                return Err(anyhow!(
                    "wallet produced psbt with too many outputs: {:?}",
                    psbt
                ));
            }
            Some(
                outputs
                    .iter()
                    .find(|output| output.script_pubkey != Script::default())
                    .map(|output| Change::new(output.value, output.script_pubkey.clone()))
                    .expect("bdk change script_pubkey will not be empty"),
            )
        } else {
            None
        };

        let mut proposal = Proposal {
            oracle: oracle_id,
            event_id: event_id.clone(),
            value,
            inputs: tx_inputs,
            public_key: crate::placeholder_point(),
            change_script: change.as_ref().map(|x| x.binscript().clone()),
        };

        let keypair = self.keychain.get_key_for_proposal(&proposal);
        proposal.public_key = keypair.public_key;

        let local_proposal = LocalProposal {
            proposal,
            oracle_event,
            change,
            tags: args.tags,
        };

        Ok(local_proposal)
    }
}
