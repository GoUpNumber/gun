// mod claim;
mod bet_args;
mod joint_output;
mod offer;
mod proposal;
mod randomize;
mod state_machine;
mod take_offer;

pub use bet_args::*;
pub use joint_output::*;
pub use offer::*;
pub use proposal::*;
pub use take_offer::*;

use crate::{
    bet::Bet,
    bet_database::{BetDatabase, BetId, BetOrProp, BetState, Claim},
    keychain::Keychain,
    reqwest, OracleInfo,
};
use anyhow::{anyhow, Context};
use bdk::{
    bitcoin::{util::psbt, Amount, OutPoint, PrivateKey, Script, TxOut, Txid},
    blockchain::{AnyBlockchain, AnyBlockchainConfig, Blockchain, ConfigurableBlockchain},
    database::MemoryDatabase,
    descriptor::ExtendedDescriptor,
    signer::SignerOrdering,
    wallet::{AddressIndex, Wallet},
    KeychainKind, SignOptions,
};
use core::{borrow::Borrow, convert::TryFrom};
use miniscript::DescriptorTrait;
use olivia_core::{
    http::{EventResponse, RootResponse},
    Attestation, EventId, OracleEvent, OracleId, Outcome,
};
use olivia_secp256k1::{
    fun::{g, marker::*, s, Scalar, G},
    Secp256k1,
};
use std::sync::Arc;

pub struct Party<B, D> {
    wallet: Wallet<B, D>,
    keychain: Keychain,
    client: crate::reqwest::Client,
    bet_db: BetDatabase,
    blockchain_config: AnyBlockchainConfig,
}

impl<D> Party<bdk::blockchain::EsploraBlockchain, D>
where
    D: bdk::database::BatchDatabase,
{
    pub fn new(
        wallet: Wallet<bdk::blockchain::EsploraBlockchain, D>,
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

    pub fn wallet(&self) -> &Wallet<bdk::blockchain::EsploraBlockchain, D> {
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
        let oracle_id = url.host_str().ok_or(anyhow!("url {} missing host", url))?;
        let event_response = self
            .client
            .get(url.clone())
            .send()
            .await?
            .error_for_status()?
            .json::<EventResponse<Secp256k1>>()
            .await?;

        let oracle_info = self
            .bet_db()
            .get_entity::<OracleInfo>(oracle_id.to_string())?
            .ok_or(anyhow!("oracle '{}' is not trusted"))?;
        let event_id = EventId::try_from(url.clone())
            .with_context(|| format!("trying to parse the path of {} for ", &url))?;

        let oracle_event = event_response
            .announcement
            .verify_against_id(&event_id, &oracle_info.oracle_keys.announcement_key)
            .ok_or(anyhow!("announcement oracle returned from {}", url))?;

        Ok(oracle_event)
    }

    pub fn new_blockchain(&self) -> anyhow::Result<AnyBlockchain> {
        Ok(AnyBlockchain::from_config(&self.blockchain_config)?)
    }

    pub fn learn_outcome(
        &self,
        bet_id: BetId,
        attestation: Attestation<Secp256k1>,
    ) -> anyhow::Result<()> {
        self.bet_db
            .update_bets(&[bet_id], move |old_state, _, txdb| match old_state {
                BetState::Confirmed { bet, .. } => {
                    let event_id = bet.oracle_event.event.id.clone();
                    let outcome = Outcome::try_from_id_and_outcome(event_id, &attestation.outcome)
                        .context("parsing oracle outcome")?;
                    let attest_scalar = Scalar::from(attestation.scalars[0].clone());
                    if let Some(oracle_info) =
                        txdb.get_entity::<OracleInfo>(bet.oracle_id.clone())?
                    {
                        if !attestation.verify_attestation(
                            &bet.oracle_event,
                            &oracle_info.oracle_keys.attestation_key,
                        ) {
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
                            assert_eq!(
                                &g!(secret_key * G),
                                joint_output.my_point(),
                                "redundant check to make sure we have right key"
                            );

                            let secret_key = secret_key
                                .mark::<NonZero>()
                                .expect("it matches the output key")
                                .into();

                            Ok(BetState::Won {
                                bet,
                                secret_key,
                                attestation: attestation.clone(),
                            })
                        }
                        _ => Ok(BetState::Lost {
                            bet,
                            attestation: attestation.clone(),
                        }),
                    }
                }
                old_state => Ok(old_state),
            })?;
        Ok(())
    }

    async fn try_get_outcome(&self, bet_id: BetId, bet: Bet) -> anyhow::Result<()> {
        let event_id = bet.oracle_event.event.id;
        let event_url = reqwest::Url::parse(&format!("https://{}{}", bet.oracle_id, event_id))?;
        let event_response = self
            .client
            .get(event_url)
            .send()
            .await?
            .error_for_status()?
            .json::<EventResponse<Secp256k1>>()
            .await?;

        if let Some(attestation) = event_response.attestation {
            self.learn_outcome(bet_id, attestation)?;
        }

        Ok(())
    }

    pub fn claim_to(
        &self,
        dest: Option<Script>,
        value: Option<Amount>,
    ) -> anyhow::Result<Option<Claim>> {
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
                } => Some((bet_id, bet, secret_key)),
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
        builder.manually_selected_only().enable_rbf();

        let recipient = dest.unwrap_or(self.wallet.get_address(AddressIndex::New)?.script_pubkey());

        match value {
            Some(value) => builder.add_recipient(recipient, value.as_sat()),
            None => builder.set_single_recipient(recipient),
        };

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
            tmp_wallet.sign(&mut psbt, SignOptions::default())?;
        }

        let finalized = self
            .wallet
            .finalize_psbt(&mut psbt, SignOptions::default())?;
        assert!(
            finalized,
            "since we have signed each input is must be finalized"
        );
        let claim_tx = psbt.extract_tx();

        self.bet_db
            .update_bets(&claimable_bet_ids[..], |bet_state, _, _| match bet_state {
                BetState::Won {
                    bet, secret_key, ..
                }
                | BetState::Claiming {
                    bet, secret_key, ..
                } => Ok(BetState::Claiming {
                    bet,
                    claim_txid: claim_tx.txid(),
                    secret_key,
                }),
                _ => Err(anyhow!("bet changed under our nose -- try again")),
            })?;

        Ok(Some(Claim {
            tx: claim_tx,
            bets: claimable_bet_ids,
        }))
    }

    pub async fn cancel(&self, bet_ids: &[BetId]) -> anyhow::Result<()> {
        let mut utxos_that_need_cancelling: Vec<OutPoint> = vec![];
        let unspent = self
            .wallet
            .list_unspent()?
            .into_iter()
            .map(|x| x.outpoint)
            .collect::<Vec<_>>();

        for bet_id in bet_ids {
            let bet_state = self.bet_db().get_entity(*bet_id)?.ok_or(anyhow!(
                "can't cancel bet {} because it doesn't exist",
                bet_id
            ))?;
            match bet_state {
                BetState::Proposed { local_proposal } => {
                    let inputs = &local_proposal.proposal.payload.inputs;
                    if inputs
                        .iter()
                        .find(|input| utxos_that_need_cancelling.contains(input))
                        .is_none()
                    {
                        utxos_that_need_cancelling.push(inputs[0]);
                    }
                }
                BetState::Offered { bet, .. } | BetState::Unconfirmed { bet, .. } => {
                    let inputs = &bet
                        .tx
                        .input
                        .iter()
                        .map(|x| x.previous_output)
                        .filter(|x| unspent.contains(x))
                        .collect::<Vec<_>>();
                    if inputs
                        .iter()
                        .find(|input| utxos_that_need_cancelling.contains(input))
                        .is_none()
                    {
                        utxos_that_need_cancelling.push(inputs[0]);
                    }
                }
                _ => {
                    return Err(anyhow!(
                        "Cannot cancel bet {} in state {}",
                        bet_id,
                        bet_state.name()
                    ))
                }
            }
        }

        self.wallet
            .sync(bdk::blockchain::noop_progress(), None)
            .await?;

        let mut builder = self.wallet.build_tx();
        builder.manually_selected_only().enable_rbf();

        for utxo in utxos_that_need_cancelling {
            match builder.add_utxo(utxo) {
                Ok(_) | Err(bdk::Error::UnknownUtxo) => {
                    // if the utxo is maigcally gone don't worry about it
                }
                Err(e) => return Err(e.into()),
            }
        }

        builder.set_single_recipient(self.wallet.get_address(AddressIndex::New)?.script_pubkey());
        let (mut psbt, _) = match builder.finish() {
            Err(bdk::Error::NoUtxosSelected) => return Ok(()),
            Ok(res) => res,
            e => e?,
        };
        let finalized = self.wallet.sign(&mut psbt, SignOptions::default())?;
        assert!(finalized, "we should have signed all inputs");
        let cancel_tx = psbt.extract_tx();
        let cancel_txid = cancel_tx.txid();

        bdk::blockchain::Broadcast::broadcast(self.wallet.client(), cancel_tx)
            .await
            .context("broadcasting cancel transaction")?;

        self.bet_db()
            .update_bets(bet_ids, |bet_state, bet_id, _| match bet_state {
                BetState::Offered { bet, .. } | BetState::Unconfirmed { bet, .. } => {
                    Ok(BetState::Cancelling {
                        cancel_txid,
                        bet_or_prop: BetOrProp::Bet(bet),
                    })
                }
                BetState::Proposed { local_proposal } => Ok(BetState::Cancelling {
                    cancel_txid,
                    bet_or_prop: BetOrProp::Proposal(local_proposal),
                }),
                _ => Err(anyhow!(
                    "Canelling bets failed because {} changed transitioned to {} -- try again!",
                    bet_id,
                    bet_state.name()
                )),
            })?;

        Ok(())
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

    pub async fn outpoint_to_psbt_input(&self, outpoint: OutPoint) -> anyhow::Result<psbt::Input> {
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

        let psbt_input = psbt::Input {
            witness_utxo: Some(txout),
            non_witness_utxo: Some(tx),
            ..Default::default()
        };
        Ok(psbt_input)
    }

    pub async fn outpoint_exists(
        &self,
        outpoint: OutPoint,
        descriptor: ExtendedDescriptor,
    ) -> anyhow::Result<bool> {
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
        Ok(wallet
            .list_unspent()?
            .iter()
            .find(|utxo| utxo.outpoint == outpoint)
            .is_some())
    }
}
