use crate::{
    bet::Bet,
    bet_database::{BetId, BetOrProp, BetState, CancelReason},
};
use anyhow::anyhow;
use bdk::{bitcoin::OutPoint, blockchain::UtxoExists};

use super::Party;

macro_rules! update_bet {
    ($self:expr, $bet_id:expr, $($tt:tt)+) => {
        $self.bet_db.update_bets(&[$bet_id], |old_state, _, _| {
            Ok(match old_state {
                $($tt)+,
                _ => old_state
            })
        })?;
    }
}

impl<D> Party<bdk::blockchain::EsploraBlockchain, D>
where
    D: bdk::database::BatchDatabase,
{
    fn check_cancelled(&self, inputs: &[OutPoint]) -> anyhow::Result<Option<CancelReason>> {
        for input in inputs {
            if !self.wallet.client().utxo_exists(*input)? {
                let tx = self.wallet.list_transactions(true)?.into_iter().find(|tx| {
                    tx.transaction
                        .as_ref()
                        .unwrap()
                        .input
                        .iter()
                        .find(|txin| txin.previous_output == *input)
                        .is_some()
                        && tx.confirmation_time.is_some()
                });
                return Ok(Some(match tx {
                    Some(tx) => CancelReason::ICancelled {
                        spent: *input,
                        my_cancelling_tx: tx.txid,
                    },
                    None => CancelReason::TheyCancelled { spent: *input },
                }));
            }
        }
        Ok(None)
    }

    /// Look at current state and see if we can progress it.
    ///
    /// The `try_learn_outcome` exists so during tests it can be turned off so this doesn't try and contact a non-existent oracle.
    /// TODO: fix this with an oracle trait that can be mocked in tests.
    pub fn take_next_action(&self, bet_id: BetId, try_learn_outcome: bool) -> anyhow::Result<()> {
        let bet_state = self
            .bet_db
            .get_entity(bet_id)?
            .ok_or(anyhow!("Bet {} does not exist"))?;

        match bet_state {
            BetState::Cancelling { bet_or_prop, .. } => {
                // success cancelling
                if let Some(reason) = self.check_cancelled(&bet_or_prop.inputs())? {
                    update_bet! {
                        self, bet_id,
                        BetState::Cancelling { bet_or_prop, .. } => BetState::Cancelled {
                            bet_or_prop,
                            reason: reason.clone()
                        }
                    };
                }
                // failed to cancel
                if let BetOrProp::Bet(bet) = bet_or_prop {
                    if let Some(height) =
                        self.is_confirmed(bet.tx().txid(), bet.joint_output.wallet_descriptor())?
                    {
                        update_bet! { self, bet_id,
                            BetState::Cancelling { .. } => BetState::Confirmed { bet: bet.clone(), height }
                        }
                    }
                }
            }
            BetState::Cancelled {
                bet_or_prop: BetOrProp::Bet(bet),
                ..
            } => {
                if let Some(height) =
                    self.is_confirmed(bet.tx().txid(), bet.joint_output.wallet_descriptor())?
                {
                    update_bet! { self, bet_id,
                                  BetState::Cancelled { .. } => BetState::Confirmed { bet: bet.clone(), height }
                    }
                }
            }
            BetState::Proposed { local_proposal } => {
                if let Some(reason) = self.check_cancelled(&local_proposal.proposal.inputs)? {
                    update_bet! { self, bet_id,
                        BetState::Proposed { local_proposal } => BetState::Cancelled {
                            bet_or_prop: BetOrProp::Proposal(local_proposal),
                            reason: reason.clone()
                        }
                    };
                }
            }
            BetState::Offered { bet, .. } => {
                let txid = bet.tx().txid();
                if let Some(height) =
                    self.is_confirmed(txid, bet.joint_output.wallet_descriptor())?
                {
                    update_bet! { self, bet_id,
                        BetState::Offered { bet, .. } => BetState::Confirmed { bet, height }
                    };
                    self.take_next_action(bet_id, try_learn_outcome)?;
                }

                let inputs_to_check_for_cancellation = bet
                    .tx()
                    .input
                    .iter()
                    .map(|x| x.previous_output)
                    .collect::<Vec<_>>();
                if let Some(reason) = self.check_cancelled(&inputs_to_check_for_cancellation)? {
                    update_bet! { self, bet_id,
                         BetState::Offered { bet, .. } => BetState::Cancelled {
                            bet_or_prop: BetOrProp::Bet(bet),
                            reason: reason.clone()
                        }
                    };
                }
            }
            BetState::Unconfirmed { bet } => {
                let txid = bet.tx().txid();

                if let Some(height) =
                    self.is_confirmed(txid, bet.joint_output.wallet_descriptor())?
                {
                    update_bet! { self, bet_id,
                        BetState::Unconfirmed { bet, .. } => BetState::Confirmed { bet, height }
                    };
                    self.take_next_action(bet_id, try_learn_outcome)?;
                } else {
                    let inputs_to_check_for_cancellation = bet
                        .tx()
                        .input
                        .iter()
                        .map(|x| x.previous_output)
                        .collect::<Vec<_>>();
                    if let Some(reason) = self.check_cancelled(&inputs_to_check_for_cancellation)? {
                        update_bet! { self, bet_id,
                            BetState::Unconfirmed { bet, .. } => {
                                BetState::Cancelled {
                                    bet_or_prop: BetOrProp::Bet(bet),
                                    reason: reason.clone()
                                }
                            }
                        };
                    }
                }
            }
            BetState::Confirmed { bet, height: _ } => {
                if try_learn_outcome {
                    self.try_get_outcome(bet_id, bet)?;
                }
            }
            BetState::Won { bet, .. } => {
                // It should never happen that you go from "Won" to "Claimed" without going through
                // claiming but just in case someone steals your keys somehow we handle it.
                if let Some(tx_that_claimed) =
                    self.get_spending_tx(bet.outpoint(), bet.joint_output.wallet_descriptor())?
                {
                    update_bet! {
                        self, bet_id,
                        BetState::Won { bet, .. } => BetState::Claimed { bet, expecting: None, txid: tx_that_claimed }
                    }
                }
            }
            BetState::Claiming { bet, .. } => {
                if let Some(tx_that_claimed) =
                    self.get_spending_tx(bet.outpoint(), bet.joint_output.wallet_descriptor())?
                {
                    update_bet! {
                        self, bet_id,
                        BetState::Claiming { bet, claim_txid, .. } => BetState::Claimed { bet, expecting: Some(claim_txid), txid: tx_that_claimed  }
                    }
                }
            }
            BetState::Claimed { .. } | BetState::Cancelled { .. } | BetState::Lost { .. } => {}
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
            .json::<crate::EventResponse>()?;

        if let Some(attestation) = event_response.attestation {
            self.learn_outcome(bet_id, attestation)?;
        }

        Ok(())
    }
}
