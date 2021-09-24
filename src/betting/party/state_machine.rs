use crate::betting::*;
use anyhow::{anyhow, Context};
use bdk::blockchain::{
    Blockchain, Broadcast, GetInputState, InputState, TransactionState, TxState,
};

use super::Party;

macro_rules! update_bet {
    ($self:expr, $bet_id:expr, $($tt:tt)+) => {
        $self.bet_db.update_bets(&[$bet_id], |old_state, _, _| {
            #[allow(unreachable_patterns)]
            Ok(match old_state {
                $($tt)+,
                _ => old_state
            })
        })?
    }
}

impl<D> Party<bdk::blockchain::EsploraBlockchain, D>
where
    D: bdk::database::BatchDatabase,
{
    /// Look at current state and see if we can progress it.
    ///
    /// The `try_learn_outcome` exists so during tests it can be turned off so this doesn't try and contact a non-existent oracle.
    /// TODO: fix this with an oracle trait that can be mocked in tests.
    pub fn take_next_action(&self, bet_id: BetId, try_learn_outcome: bool) -> anyhow::Result<()> {
        let bet_state = self
            .bet_db
            .get_entity(bet_id)?
            .ok_or(anyhow!("Bet {} does not exist"))?;
        let blockchain = self.wallet.client();

        match bet_state {
            BetState::Canceled {
                pre_cancel,
                height,
                i_intend_cancel,
                ..
            } => {
                match &pre_cancel {
                    BetOrProp::OfferedBet { bet, .. } => {
                        if let TxState::Present { height } = blockchain.tx_state(&bet.tx())? {
                            if let Some(tx) = blockchain.get_tx(&bet.tx().txid())? {
                                let bet = bet.clone().add_counterparty_sigs(tx);
                                update_bet! {
                                    self, bet_id, _ => BetState::Included {
                                        bet: bet.clone(),
                                        height
                                    }
                                };
                            }
                        }
                    }
                    BetOrProp::Bet(bet) => {
                        if let TxState::Present { height } = blockchain.tx_state(&bet.tx())? {
                            update_bet! { self, bet_id, BetState::Canceled { .. } => BetState::Included { bet: bet.clone(), height } }
                        }
                    }
                    BetOrProp::Proposal(_) => { /* no bet to check */ }
                }

                if height.is_none() {
                    match blockchain.input_state(&pre_cancel.inputs())? {
                        InputState::Spent {
                            index,
                            txid,
                            vin,
                            height,
                        } => {
                            update_bet! {
                                    self, bet_id,
                                    BetState::Canceled { pre_cancel, mut i_intend_cancel, .. } => {
                                        i_intend_cancel = i_intend_cancel || match &pre_cancel {
                                            BetOrProp::Bet(bet) | BetOrProp::OfferedBet { bet: OfferedBet(bet), .. } => bet.my_input_indexes.contains(&(index as u32)),
                                            BetOrProp::Proposal(_) => { debug_assert!(false, "unreachable. i_intend_cancel will be true here if we were in proposal state"); true }
                                        };
                                        BetState::Canceled {
                                            pre_cancel,
                                            height,
                                            cancel_txid: txid,
                                            cancel_vin: vin,
                                            bet_spent_vin: index,
                                            i_intend_cancel
                                        }
                                    }
                            }
                        }
                        // Whatever tx that caused us to be in canceling state has disappeared from mempool so roll back.
                        // If code is correct here it should be a tx we've broadcast ourselves (otherwise we wouldn't have transitioned).
                        InputState::Unspent => match &pre_cancel {
                            BetOrProp::Proposal(local_proposal) => {
                                update_bet! { self, bet_id, BetState::Canceled { height: None, .. } => BetState::Proposed { local_proposal: local_proposal.clone() } }
                            }
                            BetOrProp::OfferedBet {
                                bet,
                                encrypted_offer,
                            } => {
                                update_bet! { self, bet_id, BetState::Canceled { height: None, .. } => BetState::Offered { bet: bet.clone(), encrypted_offer: encrypted_offer.clone() }}
                            }
                            BetOrProp::Bet(bet) => {
                                if !i_intend_cancel {
                                    Broadcast::broadcast(blockchain, bet.tx())
                                        .context("broadcasting bet tx because it left mempool")?;
                                }
                                update_bet! { self, bet_id, BetState::Canceled { height: None, .. } => BetState::Included { bet: bet.clone(), height: None } }
                            }
                        },
                    }
                }
            }
            BetState::Proposed { local_proposal } => {
                if let InputState::Spent {
                    index,
                    txid,
                    vin,
                    height,
                } = blockchain.input_state(&local_proposal.proposal.inputs)?
                {
                    update_bet! { self, bet_id,
                       BetState::Proposed { local_proposal, .. } => BetState::Canceled {
                           pre_cancel: BetOrProp::Proposal(local_proposal),
                           bet_spent_vin: index,
                           cancel_txid: txid,
                           cancel_vin: vin,
                           height,
                           i_intend_cancel: true
                       }
                    }
                }
            }
            BetState::Offered { bet, .. } => {
                match blockchain.tx_state(&bet.0.tx())? {
                    TxState::Present { height } => {
                        if let Ok(Some(tx)) = blockchain.get_tx(&bet.0.tx().txid()) {
                            // when we offer a bet we don't have the full tx with signatures so if it's
                            // there lets get it from the blockchain.
                            update_bet! { self, bet_id,
                               BetState::Offered { bet, .. } => {
                                   let bet = bet.add_counterparty_sigs(tx.clone());
                                   BetState::Included { bet: bet.clone(), height }
                               }
                            }
                        }
                    }
                    TxState::Conflict {
                        txid,
                        vin,
                        vin_target,
                        height,
                    } => {
                        let i_intend_cancel = bet.my_input_indexes.contains(&vin_target);
                        if height.is_some() || i_intend_cancel {
                            update_bet! { self, bet_id,
                               BetState::Offered { bet, encrypted_offer } => BetState::Canceled {
                                   pre_cancel: BetOrProp::OfferedBet{ bet, encrypted_offer },
                                   bet_spent_vin: vin_target,
                                   cancel_txid: txid,
                                   cancel_vin: vin,
                                   height: height,
                                   i_intend_cancel,
                               }
                            }
                        }
                    }
                    TxState::NotFound => { /* we're waiting for proposer to broadcast */ }
                }
            }
            BetState::Included { bet, .. } => {
                match blockchain.tx_state(&bet.tx())? {
                    // If there's a conflict with the bet tx then we go to canceled
                    TxState::Conflict {
                        txid,
                        vin,
                        vin_target,
                        height,
                    } => update_bet! { self, bet_id,
                        BetState::Included { bet, .. } => BetState::Canceled {
                            i_intend_cancel: bet.my_input_indexes.contains(&vin_target),
                            pre_cancel: BetOrProp::Bet(bet),
                            bet_spent_vin: vin_target,
                            cancel_txid: txid,
                            cancel_vin: vin,
                            height,
                        }
                    },
                    // Update height if it gto confirmed somewhere else
                    TxState::Present { height } => update_bet! { self, bet_id,
                        BetState::Included { bet,..} => BetState::Included { bet, height }
                    },
                    TxState::NotFound => {
                        eprintln!(
                            "The bet tx for {} has fallen out of mempool -- rebroadcasting it!",
                            bet_id
                        );
                        Broadcast::broadcast(blockchain, bet.tx())?
                    }
                }
                if try_learn_outcome {
                    self.try_get_outcome(bet_id, bet)?;
                }
            }
            BetState::Won { bet, .. } => {
                // claiming but just in case someone steals your keys somehow we handle it.
                if let InputState::Spent { txid, height, .. } =
                    blockchain.input_state(&[bet.outpoint()])?
                {
                    update_bet! {self, bet_id,
                        BetState::Won { bet, secret_key, attestation } => {
                            BetState::Claimed { bet, txid, height, secret_key, attestation }
                        }
                    }
                }
            }
            // TODO: To be more robust, check if height is below some threshold rather than just None
            BetState::Claimed {
                bet, height: None, ..
            } => match blockchain.input_state(&[bet.outpoint()])? {
                InputState::Spent { txid, height, .. } => update_bet! {self, bet_id,
                   BetState::Claimed { bet, attestation, secret_key, .. } => BetState::Claimed { bet, txid, height, secret_key, attestation}
                },
                InputState::Unspent => update_bet! { self, bet_id,
                   BetState::Claimed { bet, secret_key, attestation, .. } => BetState::Won { bet, secret_key, attestation }
                },
            },
            BetState::Claimed {
                height: Some(_), ..
            }
            | BetState::Lost { .. } => { /* terminal states */ }
        }
        Ok(())
    }

    fn try_get_outcome(&self, bet_id: BetId, bet: Bet) -> anyhow::Result<()> {
        let event_id = bet.oracle_event.event.id;
        let event_url = reqwest::Url::parse(&format!("https://{}{}", bet.oracle_id, event_id))?;
        let event_response = self
            .client
            .get(event_url)
            .send()?
            .error_for_status()?
            .json::<EventResponse>()?;

        if let Some(attestation) = event_response.attestation {
            self.learn_outcome(bet_id, attestation)?;
        }

        Ok(())
    }
}
