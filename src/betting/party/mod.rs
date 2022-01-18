mod bet_args;
mod offer;
mod proposal;
mod spend_won;
mod state_machine;
mod take_offer;

pub use bet_args::*;
use miniscript::DescriptorTrait;

use crate::{betting::*, keychain::Keychain, FeeSpec};
use anyhow::{anyhow, Context};
use bdk::{
    bitcoin::{
        util::psbt::{self, PartiallySignedTransaction as Psbt},
        OutPoint, Txid,
    },
    blockchain::{
        noop_progress, AnyBlockchain, AnyBlockchainConfig, Blockchain, ConfigurableBlockchain,
    },
    database::MemoryDatabase,
    descriptor::ExtendedDescriptor,
    wallet::{AddressIndex, Wallet},
    KeychainKind, SignOptions,
};
use olivia_core::{Attestation, Outcome};
use olivia_secp256k1::{
    fun::{g, marker::*, s, Scalar, G},
    Secp256k1,
};

pub struct Party<B, D> {
    wallet: Wallet<B, D>,
    pub(crate) keychain: Keychain,
    client: ureq::Agent,
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
            client: ureq::Agent::new(),
            blockchain_config,
        }
    }

    pub fn wallet(&self) -> &Wallet<bdk::blockchain::EsploraBlockchain, D> {
        &self.wallet
    }

    pub fn bet_db(&self) -> &BetDatabase {
        &self.bet_db
    }

    pub fn trust_oracle(&self, oracle_info: OracleInfo) -> anyhow::Result<()> {
        self.bet_db.insert_oracle_info(oracle_info)
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
                BetState::Included { bet, .. } => {
                    let event_id = bet.oracle_event.event.id.clone();
                    let outcome = Outcome::try_from_id_and_outcome(event_id, &attestation.outcome)
                        .context("parsing oracle outcome")?;
                    let olivia_v1_scalars = &attestation
                        .schemes
                        .olivia_v1
                        .as_ref()
                        .ok_or(anyhow!("attestation is missing olivia-v1"))?
                        .scalars;
                    let attest_scalar = Scalar::from(olivia_v1_scalars[0].clone());
                    if let Some(oracle_info) =
                        txdb.get_entity::<OracleInfo>(bet.oracle_id.clone())?
                    {
                        attestation
                            .verify_olivia_v1_attestation(
                                &bet.oracle_event,
                                &oracle_info.oracle_keys,
                            )
                            .context("Oracle gave invalid attestation")?;
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

    pub fn generate_cancel_tx(
        &self,
        bet_ids: &[BetId],
        feespec: FeeSpec,
    ) -> anyhow::Result<Option<Psbt>> {
        let mut utxos_that_need_canceling: Vec<OutPoint> = vec![];

        for bet_id in bet_ids {
            let bet_state = self.bet_db().get_entity(*bet_id)?.ok_or(anyhow!(
                "can't cancel bet {} because it doesn't exist",
                bet_id
            ))?;
            match bet_state {
                BetState::Proposed { local_proposal } => {
                    let inputs = &local_proposal.proposal.inputs;
                    if !inputs
                        .iter()
                        .any(|input| utxos_that_need_canceling.contains(input))
                    {
                        utxos_that_need_canceling.push(inputs[0]);
                    }
                }
                BetState::Canceled {
                    height: None,
                    pre_cancel: BetOrProp::Bet(bet),
                    ..
                }
                | BetState::Canceled {
                    height: None,
                    pre_cancel:
                        BetOrProp::OfferedBet {
                            bet: OfferedBet(bet),
                            ..
                        },
                    ..
                }
                | BetState::Offered {
                    bet: OfferedBet(bet),
                    ..
                }
                | BetState::Included {
                    bet, height: None, ..
                } => {
                    let tx = bet.tx();
                    let inputs = bet
                        .my_input_indexes
                        .iter()
                        .map(|i| tx.input[*i as usize].previous_output)
                        .collect::<Vec<_>>();
                    if !inputs
                        .iter()
                        .any(|input| utxos_that_need_canceling.contains(input))
                    {
                        utxos_that_need_canceling.push(inputs[0]);
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

        let mut builder = self.wallet.build_tx();
        builder
            .manually_selected_only()
            .enable_rbf()
            .only_witness_utxo();
        feespec.apply_to_builder(self.wallet.client(), &mut builder)?;

        for utxo in utxos_that_need_canceling {
            // we have to add these as foreign UTXOs because BDK doesn't let you spend
            // outputs that have been spent by tx in the mempool.
            let tx = match self.wallet.query_db(|db| db.get_tx(&utxo.txid, true))? {
                Some(tx) => tx,
                None => {
                    debug_assert!(false, "we should always be able to find our tx");
                    continue;
                }
            };
            let txout = tx.transaction.as_ref().unwrap().output[utxo.vout as usize].clone();
            let psbt_input = psbt::Input {
                witness_utxo: Some(txout.clone()),
                ..Default::default()
            };
            let satisfaction_weight = self
                .wallet
                .get_descriptor_for_script_pubkey(&txout.script_pubkey)?
                .expect("should exist in database")
                .max_satisfaction_weight()?;
            builder.add_foreign_utxo(utxo, psbt_input, satisfaction_weight)?;
        }

        builder.drain_to(
            self.wallet
                .get_change_address(AddressIndex::New)?
                .script_pubkey(),
        );
        let (mut psbt, _) = match builder.finish() {
            Err(bdk::Error::NoUtxosSelected) => return Ok(None),
            Ok(res) => res,
            e => e?,
        };
        let finalized = self.wallet.sign(
            &mut psbt,
            SignOptions {
                trust_witness_utxo: true,
                ..Default::default()
            },
        )?;
        assert!(finalized, "we should have signed all inputs");
        Ok(Some(psbt))
    }

    pub fn is_confirmed(
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
        )?;
        wallet.sync(bdk::blockchain::noop_progress(), None)?;
        Ok(wallet
            .list_transactions(true)?
            .iter()
            .find_map(|tx| match &tx.confirmation_time {
                Some(confirmation_time) if tx.txid == txid => Some(confirmation_time.height),
                _ => None,
            }))
    }

    // the reason we require p2wpkh inputs here is so the witness is non-malleable.
    // What to do about TR outputs in the future I haven't decided.
    pub fn p2wpkh_outpoint_to_psbt_input(&self, outpoint: OutPoint) -> anyhow::Result<psbt::Input> {
        let tx = self
            .wallet
            .client()
            .get_tx(&outpoint.txid)?
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

        if !txout.script_pubkey.is_v0_p2wpkh() {
            return Err(anyhow!("outpoint {} was not p2wpkh", outpoint));
        }

        let psbt_input = psbt::Input {
            witness_utxo: Some(txout),
            non_witness_utxo: Some(tx),
            ..Default::default()
        };
        Ok(psbt_input)
    }

    // convenience methods
    pub fn sync(&self) -> anyhow::Result<()> {
        eprintln!("syncing wallet with {:?}", self.blockchain_config);
        self.wallet.sync(noop_progress(), None)?;
        Ok(())
    }

    pub fn poke_bets(&self) {
        for (bet_id, _) in self.bet_db().list_entities_print_error::<BetState>() {
            match self.take_next_action(bet_id, true) {
                Ok(_updated) => {}
                Err(e) => eprintln!("Error trying to take action on bet {}: {:?}", bet_id, e),
            }
        }
    }
}
