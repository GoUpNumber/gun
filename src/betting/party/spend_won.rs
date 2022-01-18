use crate::{betting::*, FeeSpec};
use bdk::{
    bitcoin::{
        util::psbt::{self, PartiallySignedTransaction as Psbt},
        PrivateKey, TxOut,
    },
    blockchain::Blockchain,
    database::MemoryDatabase,
    miniscript::DescriptorTrait,
    signer::SignerOrdering,
    wallet::{coin_selection::CoinSelectionAlgorithm, tx_builder::TxBuilderContext, AddressIndex},
    KeychainKind, SignOptions, TxBuilder, Wallet,
};
use std::sync::Arc;

use super::Party;

impl<D> Party<bdk::blockchain::EsploraBlockchain, D>
where
    D: bdk::database::BatchDatabase,
{
    pub fn claim(
        &self,
        fee: FeeSpec,
        bump_claiming: bool,
    ) -> anyhow::Result<Option<(Vec<BetId>, Psbt)>> {
        let wallet = self.wallet();
        let mut builder = wallet.build_tx();
        builder.manually_selected_only().enable_rbf();

        fee.apply_to_builder(wallet.client(), &mut builder)?;

        let recipient = wallet
            .get_change_address(AddressIndex::New)?
            .script_pubkey();

        builder.drain_to(recipient);

        let (mut psbt, claiming_bet_ids) = match self.spend_won_bets(builder, bump_claiming)? {
            Some(res) => res,
            None => return Ok(None),
        };

        let finalized = wallet.finalize_psbt(&mut psbt, SignOptions::default())?;

        assert!(
            finalized,
            "since we have signed each input is must be finalized"
        );

        Ok(Some((claiming_bet_ids, psbt)))
    }

    pub fn spend_won_bets<B: Blockchain, Cs: CoinSelectionAlgorithm<D>, Ctx: TxBuilderContext>(
        &self,
        mut builder: TxBuilder<'_, B, D, Cs, Ctx>,
        bump_claiming: bool,
    ) -> anyhow::Result<Option<(Psbt, Vec<BetId>)>> {
        let claimable_bets = self
            .bet_db
            .list_entities::<BetState>()
            .filter_map(|result| match result {
                Ok(ok) => Some(ok),
                Err(e) => {
                    eprintln!("Eror with entry in database: {}", e);
                    None
                }
            })
            .filter_map(|(bet_id, bet_state)| match bet_state {
                BetState::Won {
                    bet, secret_key, ..
                } => Some((bet_id, bet, secret_key)),
                BetState::Claimed {
                    height: None,
                    bet,
                    secret_key,
                    ..
                } if bump_claiming => Some((bet_id, bet, secret_key)),
                _ => None,
            })
            .collect::<Vec<_>>();

        let claimable_bet_ids = claimable_bets
            .iter()
            .map(|(bet_id, _, _)| *bet_id)
            .collect::<Vec<_>>();

        for (_, bet, _) in &claimable_bets {
            let psbt_input = psbt::Input {
                witness_utxo: Some(TxOut {
                    value: bet.joint_output_value.as_sat(),
                    script_pubkey: bet.joint_output.descriptor().script_pubkey().unwrap(),
                }),
                non_witness_utxo: Some(bet.tx()),
                witness_script: Some(bet.joint_output.descriptor().script_code().unwrap()),
                ..Default::default()
            };
            builder
                .add_foreign_utxo(
                    bet.outpoint(),
                    psbt_input,
                    bet.joint_output
                        .descriptor()
                        .max_satisfaction_weight()
                        .unwrap(),
                )
                .unwrap();
        }

        let (mut psbt, _) = match builder.finish() {
            Ok(res) => res,
            Err(bdk::Error::NoUtxosSelected) => return Ok(None),
            e => e?,
        };

        for (_, bet, secret_key) in claimable_bets {
            let signer = PrivateKey {
                compressed: true,
                network: self.wallet.network(),
                key: secret_key,
            };
            let output_descriptor = bet.joint_output.wallet_descriptor();
            let mut tmp_wallet = Wallet::new_offline(
                output_descriptor,
                None,
                self.wallet.network(),
                MemoryDatabase::default(),
            )
            .expect("nothing can go wrong here");
            tmp_wallet.add_signer(
                KeychainKind::External,
                SignerOrdering::default(),
                Arc::new(signer),
            );
            tmp_wallet.sign(&mut psbt, SignOptions::default())?;
        }

        Ok(Some((psbt, claimable_bet_ids)))
    }
}
