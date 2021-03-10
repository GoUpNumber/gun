// mod claim;
mod joint_output;
mod offer;
mod proposal;
mod randomize;
mod take_offer;
mod tx_tracker;

use bdk::{
    bitcoin::{util::psbt, OutPoint, PrivateKey, Script, TxOut, Txid},
    blockchain::EsploraBlockchain,
    database::MemoryDatabase,
    descriptor::ExtendedDescriptor,
    signer::Signer,
};
pub use joint_output::*;
use miniscript::DescriptorTrait;
pub use proposal::*;
pub use tx_tracker::*;

use crate::{
    bet_database::{BetDatabase, BetId, BetState, Claim},
    keychain::Keychain,
    reqwest,
};
use anyhow::{anyhow, Context};
use bdk::wallet::Wallet;
use core::borrow::Borrow;
pub use offer::*;
use olivia_core::{
    http::{EventResponse, RootResponse},
    OracleEvent, OracleId, OracleInfo,
};
use olivia_secp256k1::{
    fun::{g, marker::*, s, Scalar, G},
    Secp256k1,
};

pub struct Party<B, D, BD> {
    wallet: Wallet<B, D>,
    keychain: Keychain,
    client: crate::reqwest::Client,
    bets_db: BD,
    #[allow(dead_code)]
    esplora_url: String,
}

impl<B, D, BD> Party<B, D, BD>
where
    BD: BetDatabase,
    B: bdk::blockchain::Blockchain,
    D: bdk::database::BatchDatabase,
{
    pub fn new(wallet: Wallet<B, D>, bets_db: BD, keychain: Keychain, esplora_url: String) -> Self {
        Self {
            wallet,
            keychain,
            bets_db,
            client: crate::reqwest::Client::new(),
            esplora_url,
        }
    }

    pub fn wallet(&self) -> &Wallet<B, D> {
        &self.wallet
    }

    pub fn bet_db(&self) -> &BD {
        &self.bets_db
    }

    pub async fn save_oracle_info(
        &self,
        oracle_id: OracleId,
    ) -> anyhow::Result<OracleInfo<Secp256k1>> {
        dbg!(&oracle_id);
        match self.bets_db.borrow().get_oracle_info(&oracle_id)? {
            Some(oracle_info) => Ok(oracle_info),
            None => {
                let root_resposne = self
                    .client
                    .get(&format!("https://{}", &oracle_id))
                    .send()
                    .await?
                    .error_for_status()?
                    .json::<RootResponse<Secp256k1>>()
                    .await?;

                let oracle_info = OracleInfo {
                    id: oracle_id,
                    public_key: root_resposne.public_key,
                };

                self.bets_db.insert_oracle_info(oracle_info.clone())?;
                Ok(oracle_info)
            }
        }
    }

    pub async fn get_oracle_event_from_url(
        &self,
        url: reqwest::Url,
    ) -> anyhow::Result<OracleEvent<Secp256k1>> {
        let event_response = self
            .client
            .get(url.clone())
            .send()
            .await?
            .error_for_status()?
            .json::<EventResponse<Secp256k1>>()
            .await?;

        Ok(event_response
            .announcement
            .oracle_event
            .decode()
            .ok_or(anyhow!("unable to decode oracle event at {}", url))?)
    }

    pub fn new_blockchain(&self) -> EsploraBlockchain {
        EsploraBlockchain::new(&self.esplora_url, None)
    }

    pub async fn get_txout(&self, outpoint: OutPoint) -> anyhow::Result<TxOut> {
        let tx = self
            .wallet
            .client()
            .get_tx(&outpoint.txid)
            .await?
            .ok_or(anyhow!("txid not found {}", outpoint.txid))?;

        let txout = tx
            .output
            .get(outpoint.vout as usize)
            .ok_or(anyhow!(
                "vout {} doesn't exist on txid {}",
                outpoint.vout,
                outpoint.txid
            ))?
            .clone();
        Ok(txout)
    }

    pub async fn take_next_action(&self, bet_id: BetId) -> anyhow::Result<bool> {
        let mut took_any_action = false;

        let bet_state = self
            .bets_db
            .get_bet(bet_id)?
            .ok_or(anyhow!("Bet {} does not exist"))?;
        match bet_state {
            BetState::Proposed { .. }
            | BetState::Offered { .. } // offered needs to be its own thing
            | BetState::Confirmed { .. }
            | BetState::Won { .. }
            | BetState::Lost { .. } => {}
            BetState::Unconfirmed {
                funding_transaction,
                has_broadcast: false,
                ..
            } => {
                let txid = funding_transaction.txid();
                self.wallet
                    .broadcast(funding_transaction)
                    .await
                    .context(format!(
                        "Failed to broadcast funding transaction with txid {} for bet {}",
                        txid, bet_id
                    ))?;
                self.bets_db.update_bet(bet_id, move |old_state| match old_state {
                    BetState::Unconfirmed { bet, funding_transaction, has_broadcast: false } =>  {
                        Ok(BetState::Unconfirmed { bet, funding_transaction, has_broadcast: true })
                    },
                    old_state => Ok(old_state)
                })?;
                return Ok(true)
            },
            BetState::Unconfirmed {
                funding_transaction,
                bet,
                has_broadcast: true
            } => {
                let txid = funding_transaction.txid();
                if let Some(height) = self
                    .is_confirmed(txid, bet.joint_output.wallet_descriptor())
                    .await?
                {
                    self.bets_db
                        .update_bet(bet_id, move |old_state| match old_state {
                            BetState::Unconfirmed { bet, .. } => {
                                Ok(BetState::Confirmed { bet, height })
                            }
                            _ => Ok(old_state),
                        })?;
                    took_any_action = true;
                }
            }
        }
        Ok(took_any_action)
    }

    pub fn claim_to(&self, dest: Option<Script>) -> anyhow::Result<Option<Claim>> {
        let claimable_bets = self
            .bets_db
            .list_bets()?
            .into_iter()
            .map(|bet_id| -> anyhow::Result<_> {
                Ok((bet_id, self.bets_db.get_bet(bet_id)?.unwrap()))
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter_map(|(bet_id, bet_state)| match bet_state {
                BetState::Won { bet, secret_key } => Some((bet_id, bet, secret_key)),
                _ => None,
            })
            .collect::<Vec<_>>();

        let claimable_bet_ids = claimable_bets
            .iter()
            .map(|(bet_id, _, _)| *bet_id)
            .collect::<Vec<_>>();

        if claimable_bet_ids.is_empty() {
            return Ok(None);
        }

        let mut builder = self.wallet.build_tx();
        builder
            .manually_selected_only()
            .set_single_recipient(dest.unwrap_or(self.wallet.get_new_address()?.script_pubkey()))
            .enable_rbf();

        for (_, bet, _) in &claimable_bets {
            let psbt_input = psbt::Input {
                witness_utxo: Some(TxOut {
                    value: bet.value.as_sat(),
                    script_pubkey: bet.joint_output.descriptor().script_pubkey(),
                }),
                ..Default::default()
            };
            builder
                .add_foreign_utxo(
                    bet.outpoint,
                    psbt_input,
                    bet.joint_output
                        .descriptor()
                        .max_satisfaction_weight()
                        .unwrap(),
                )
                .unwrap();
        }

        let (mut psbt, _) = builder.finish()?;

        for (_, bet, secret_key) in claimable_bets {
            let signer = PrivateKey {
                compressed: true,
                network: self.wallet.network(),
                key: secret_key,
            };
            let (i, _) = psbt
                .inputs
                .iter_mut()
                .enumerate()
                .find(|(_i, psbt_input)| {
                    psbt_input.witness_utxo.as_ref().unwrap().script_pubkey
                        == bet.joint_output.descriptor().script_pubkey()
                })
                .unwrap();
            signer
                .sign(&mut psbt, Some(i), self.wallet.secp_ctx())
                .expect("it has already been checked that this is the correct key for this input");
        }

        let (psbt, finalized) = self.wallet.finalize_psbt(psbt, None)?;
        assert!(
            finalized,
            "since we have signed each input is must be finalized"
        );
        let tx = psbt.extract_tx();

        Ok(Some(Claim {
            tx,
            bets: claimable_bet_ids,
        }))
    }

    pub fn learn_outcome(
        &self,
        bet_id: BetId,
        attestation: Either<Scalar<Public>>,
    ) -> anyhow::Result<()> {
        self.bets_db
            .update_bet(bet_id, move |old_state| match old_state {
                BetState::Confirmed { bet, .. } => {
                    let joint_output = &bet.joint_output;
                    match (&attestation, &joint_output.my_key) {
                        (Either::Left(att), Either::Left(my_key))
                        | (Either::Right(att), Either::Right(my_key)) => {
                            let secret_key = s!(att + my_key);
                            if &g!(secret_key * G) != joint_output.my_point() {
                                return Err(anyhow!("Oracle gave wrong attestation"));
                            }
                            let secret_key = secret_key
                                .mark::<NonZero>()
                                .expect("it matches the output key")
                                .into();
                            Ok(BetState::Won { bet, secret_key })
                        }
                        _ => Ok(BetState::Lost { bet }),
                    }
                }
                old_state => Ok(old_state),
            })?;
        Ok(())
    }

    pub async fn is_confirmed(
        &self,
        txid: Txid,
        descriptor: ExtendedDescriptor,
    ) -> anyhow::Result<Option<u32>> {
        let blockchain = self.new_blockchain();
        let wallet = Wallet::new(
            descriptor,
            None,
            self.wallet.network(),
            MemoryDatabase::default(),
            blockchain,
        )
        .await?;
        wallet.sync(bdk::blockchain::noop_progress(), None).await?;
        Ok(wallet.list_transactions(true)?.iter().find_map(|tx| {
            if tx.txid == txid && tx.height.is_some() {
                Some(tx.height.unwrap())
            } else {
                None
            }
        }))
    }
}
