// mod claim;
mod joint_output;
mod offer;
mod proposal;
mod randomize;
mod take_offer;
mod tx_tracker;

use crate::{OracleInfo, bet::Bet, bet_database::{BetDatabase, BetId, BetState, Claim}, keychain::Keychain, reqwest};
use anyhow::{anyhow, Context};
use bdk::{KeychainKind, bitcoin::{Amount, OutPoint, PrivateKey, Script, TxOut, Txid, util::psbt}, blockchain::{AnyBlockchain, AnyBlockchainConfig, ConfigurableBlockchain}, database::MemoryDatabase, descriptor::ExtendedDescriptor, signer::SignerOrdering, wallet::{AddressIndex, Wallet}};
use olivia_core::{Attestation, OracleEvent, OracleId, Outcome, http::{EventResponse, RootResponse}};
use olivia_secp256k1::{
    fun::{g, marker::*, s, Scalar, G},
    Secp256k1,
};
use std::sync::Arc;
use miniscript::DescriptorTrait;
use core::borrow::Borrow;

pub use joint_output::*;
pub use offer::*;
pub use take_offer::*;
pub use proposal::*;
pub use tx_tracker::*;

pub struct Party<B, D> {
    wallet: Wallet<B, D>,
    keychain: Keychain,
    client: crate::reqwest::Client,
    bet_db: BetDatabase,
    blockchain_config: AnyBlockchainConfig,
}

impl<B, D> Party<B, D>
where
    B: bdk::blockchain::Blockchain,
    D: bdk::database::BatchDatabase,
{
    pub fn new(
        wallet: Wallet<B, D>,
        bet_db: BetDatabase,
        keychain: Keychain,
        blockchain_config: AnyBlockchainConfig,
    ) -> Self {
        Self {
            wallet,
            keychain,
            bet_db,
            client: crate::reqwest::Client::new(),
            blockchain_config,
        }
    }

    pub fn wallet(&self) -> &Wallet<B, D> {
        &self.wallet
    }

    pub fn bet_db(&self) -> &BetDatabase {
        &self.bet_db
    }

    pub async fn save_oracle_info(&self, oracle_id: OracleId) -> anyhow::Result<OracleInfo> {
        match self.bet_db.borrow().get_entity(oracle_id.clone())? {
            Some(oracle_info) => Ok(oracle_info),
            None => {
                let root_response = self
                    .client
                    .get(&format!("https://{}", &oracle_id))
                    .send()
                    .await?
                    .error_for_status()?
                    .json::<RootResponse<Secp256k1>>()
                    .await?;

                let oracle_info = OracleInfo {
                    id: oracle_id,
                    oracle_keys: root_response.public_keys,
                };

                self.bet_db.insert_oracle_info(oracle_info.clone())?;
                Ok(oracle_info)
            }
        }
    }

    pub fn trust_oracle(&self, oracle_info: OracleInfo) -> anyhow::Result<()> {
        self.bet_db.insert_oracle_info(oracle_info)
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

    pub fn new_blockchain(&self) -> anyhow::Result<AnyBlockchain> {
        Ok(AnyBlockchain::from_config(&self.blockchain_config)?)
    }

    pub async fn take_next_action(&self, bet_id: BetId) -> anyhow::Result<()> {

        let bet_state = self
            .bet_db
            .get_entity(bet_id)?
            .ok_or(anyhow!("Bet {} does not exist"))?;

        match bet_state {
            BetState::Proposed { .. }
            | BetState::Won { .. }
            | BetState::Claimed { .. }
            | BetState::Lost { .. } => {}
            BetState::Offered { bet } => {
                let txid = bet.outpoint.txid;
                if let Some(height) = self
                    .is_confirmed(txid, bet.joint_output.wallet_descriptor())
                    .await?
                {
                    self.bet_db
                        .update_bets(&[bet_id], move |old_state, _| match old_state {
                            BetState::Offered { bet } => Ok(BetState::Confirmed { bet, height }),
                            _ => Ok(old_state),
                        })?;
                }
            }
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
                self.bet_db
                    .update_bets(&[bet_id], move |old_state, _| match old_state {
                        BetState::Unconfirmed {
                            bet,
                            funding_transaction,
                            has_broadcast: false,
                        } => Ok(BetState::Unconfirmed {
                            bet,
                            funding_transaction,
                            has_broadcast: true,
                        }),
                        old_state => Ok(old_state),
                    })?;
            }
            BetState::Unconfirmed {
                funding_transaction,
                bet,
                has_broadcast: true,
            } => {
                let txid = funding_transaction.txid();
                if let Some(height) = self
                    .is_confirmed(txid, bet.joint_output.wallet_descriptor())
                    .await?
                {
                    self.bet_db
                        .update_bets(&[bet_id], move |old_state, _| match old_state {
                            BetState::Unconfirmed { bet, .. } => {
                                Ok(BetState::Confirmed { bet, height })
                            }
                            _ => Ok(old_state),
                        })?;
                    self.wallet.sync(bdk::blockchain::noop_progress(), None).await?;
                }
            }
            BetState::Confirmed {
                bet,
                height: _,
            } => {
                self.try_get_outcome(bet_id, bet).await?;
            }
            BetState::Claiming { bet, .. } => {
                let has_been_claimed = self.outpoint_exists(bet.outpoint, bet.joint_output.wallet_descriptor()).await?;
                if has_been_claimed {
                    self.bet_db.update_bets(&[bet_id], move |old_state, _| Ok(match old_state {
                        BetState::Claiming { bet, .. } => {
                            BetState::Claimed { bet }
                        }
                        _ => old_state
                    }))?;
                }
            }
        }
        Ok(())
    }

    pub fn learn_outcome(
        &self,
        bet_id: BetId,
        attestation: Attestation<Secp256k1>,
    ) -> anyhow::Result<()> {

        self.bet_db
            .update_bets(&[bet_id], move |old_state, txdb| match old_state {
                BetState::Confirmed { bet, .. } => {
                    let event_id = bet.oracle_event.event.id.clone();
                    let outcome = Outcome::try_from_id_and_outcome(event_id, &attestation.outcome).context("parsing oracle outcome")?;
                    let attest_scalar = Scalar::from(attestation.scalars[0].clone());
                    if let Some(oracle_info) =  txdb.get_entity::<OracleInfo>(bet.oracle_id.clone())? {
                        if !attestation.verify_attestation(&bet.oracle_event, &oracle_info.oracle_keys.attestation_key) {
                            return Err(anyhow!("Oracle gave wrong attestation"));
                        }
                    }

                    let joint_output = &bet.joint_output;
                    match (outcome.value, bet.i_chose_right) {
                        (0, false) | (1, true) => {
                                let my_key = match &joint_output.my_key {
                                    Either::Left(my_key) => my_key,
                                    Either::Right(my_key) => my_key,
                                };
                                let secret_key = s!(attest_scalar + my_key);
                                assert_eq!(&g!(secret_key * G), joint_output.my_point(), "redundant check to make sure we have right key" );

                                let secret_key = secret_key
                                    .mark::<NonZero>()
                                    .expect("it matches the output key")
                                    .into();

                                Ok(BetState::Won { bet, secret_key, attestation: attestation.clone()  })
                            }
                        _ => Ok(BetState::Lost { bet, attestation: attestation.clone() }),
                    }
                }
                old_state => Ok(old_state),
            })?;
        Ok(())
    }

    async fn try_get_outcome(&self, bet_id: BetId, bet: Bet) -> anyhow::Result<()> {
        let event_id = bet.oracle_event.event.id;
        let event_url = reqwest::Url::parse(&format!("https://{}{}", bet.oracle_id, event_id))?;
        let event_response = self.client.get(event_url)
                   .send()
                   .await?
        .error_for_status()?
        .json::<EventResponse<Secp256k1>>()
            .await?;


        if let Some(attestation)  = event_response.attestation {
            self.learn_outcome(bet_id, attestation)?;
        }

        Ok(())
    }


    pub fn claim_to(&self, dest: Option<Script>, value: Option<Amount>) -> anyhow::Result<Option<Claim>> {
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
                BetState::Won { bet, secret_key, ..  } => Some((bet_id, bet, secret_key)),
                BetState::Claiming { bet, secret_key, .. } => Some((bet_id, bet, secret_key)),
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
            .enable_rbf();

        let recipient = dest.unwrap_or(self.wallet.get_address(AddressIndex::New)?.script_pubkey());

        match value {
            Some(value) => builder.add_recipient(recipient, value.as_sat()),
            None => builder.set_single_recipient(recipient)
        };

        for (_, bet, _) in &claimable_bets {
            let psbt_input = psbt::Input {
                witness_utxo: Some(TxOut {
                    value: bet.joint_output_value.as_sat(),
                    script_pubkey: bet.joint_output.descriptor().script_pubkey(),
                }),
                witness_script: Some(bet.joint_output.descriptor().script_code()),
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
            tmp_wallet.sign(&mut psbt, None)?;
        }

        let finalized = self.wallet.finalize_psbt(&mut psbt, None)?;
        assert!(
            finalized,
            "since we have signed each input is must be finalized"
        );
        let claim_tx = psbt.extract_tx();

        self.bet_db.update_bets(&claimable_bet_ids[..], |bet_state, _|
            match bet_state {
               BetState::Won { bet, secret_key, .. }| BetState::Claiming { bet, secret_key, .. } => Ok(BetState::Claiming {
                   bet,
                   claim_txid: claim_tx.txid(),
                   secret_key,
               }),
               _ => Err(anyhow!("bet changed under our nose -- try again"))
            }
        )?;

        Ok(Some(Claim {
            tx: claim_tx,
            bets: claimable_bet_ids,
        }))
    }

    pub async fn is_confirmed(
        &self,
        txid: Txid,
        // output in transaction
        descriptor: ExtendedDescriptor,
    ) -> anyhow::Result<Option<u32>> {
        let blockchain = self.new_blockchain()?;
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

    pub async fn outpoint_exists(&self, outpoint: OutPoint, descriptor: ExtendedDescriptor) -> anyhow::Result<bool> {
        let blockchain = self.new_blockchain()?;
        let wallet = Wallet::new(
            descriptor,
            None,
            self.wallet.network(),
            MemoryDatabase::default(),
            blockchain,
        ).await?;
        wallet.sync(bdk::blockchain::noop_progress(), None).await?;
        Ok(wallet.list_unspent()?.iter().find(|utxo| utxo.outpoint == outpoint).is_some())
    }
}
