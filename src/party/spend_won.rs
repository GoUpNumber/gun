use crate::{FeeSpec, bet_database::{BetId, BetState}};
use anyhow::anyhow;
use bdk::{KeychainKind, SignOptions, TxBuilder, Wallet, bitcoin::{PrivateKey, Transaction, TxOut, Txid, util::psbt::{self, PartiallySignedTransaction as Psbt}}, blockchain::Blockchain, database::MemoryDatabase, signer::SignerOrdering, wallet::{coin_selection::CoinSelectionAlgorithm, tx_builder::TxBuilderContext}, wallet::AddressIndex};
use miniscript::DescriptorTrait;
use std::sync::Arc;

use super::Party;

impl<D> Party<bdk::blockchain::EsploraBlockchain, D>
where
    D: bdk::database::BatchDatabase,
{

    pub async fn claim(&self, fee: FeeSpec, bump_claiming: bool) -> anyhow::Result<Option<Transaction>> {
        let wallet = self.wallet();
        let mut builder = wallet.build_tx();
        builder.manually_selected_only().enable_rbf();

        fee.apply_to_builder(wallet.client(), &mut builder).await?;

        let recipient = wallet.get_address(AddressIndex::New)?.script_pubkey();

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
        let claim_tx = psbt.extract_tx();

        self.set_bets_to_claiming(&claiming_bet_ids, claim_tx.txid())?;

        Ok(Some(claim_tx))
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
                BetState::Claiming {
                    bet, secret_key, ..
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
                    script_pubkey: bet.joint_output.descriptor().script_pubkey(),
                }),
                non_witness_utxo: Some(bet.tx.clone()),
                witness_script: Some(bet.joint_output.descriptor().script_code()),
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
            e => e?
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

    pub fn set_bets_to_claiming(
        &self,
        claiming_bet_ids: &[BetId],
        claim_txid: Txid,
    ) -> anyhow::Result<()> {
        self.bet_db
            .update_bets(claiming_bet_ids, |bet_state, _, _| match bet_state {
                BetState::Won {
                    bet, secret_key, ..
                }
                | BetState::Claiming {
                    bet, secret_key, ..
                } => Ok(BetState::Claiming {
                    bet,
                    claim_txid,
                    secret_key,
                }),
                _ => Err(anyhow!("bet changed under our nose -- try again")),
            })?;
        Ok(())
    }
}
