use crate::bet_database::{BetId, BetOrProp, BetState, CancelReason};
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
    async fn check_cancelled(&self, inputs: &[OutPoint]) -> anyhow::Result<Option<CancelReason>> {
        for input in inputs {
            if !self.wallet.client().utxo_exists(*input).await? {
                dbg!("==> ", &input);
                //TOOD: only sync one address
                self.wallet
                    .sync(bdk::blockchain::noop_progress(), None)
                    .await?;
                let tx = self.wallet.list_transactions(true)?.into_iter().find(|tx| {
                    tx.transaction
                        .as_ref()
                        .unwrap()
                        .input
                        .iter()
                        .find(|txin| txin.previous_output == *input)
                        .is_some()
                        && tx.height.is_some()
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

    pub async fn take_next_action(&self, bet_id: BetId) -> anyhow::Result<()> {
        let bet_state = self
            .bet_db
            .get_entity(bet_id)?
            .ok_or(anyhow!("Bet {} does not exist"))?;

        match bet_state {
            BetState::Won { .. }
            | BetState::Claimed { .. }
            | BetState::Cancelled { .. }
            | BetState::Lost { .. } => {}
            BetState::Cancelling { bet_or_prop, .. } => {
                if let Some(reason) = self.check_cancelled(&bet_or_prop.inputs()).await? {
                    update_bet! {
                        self, bet_id,
                        BetState::Cancelling { bet_or_prop, .. } => BetState::Cancelled {
                            bet_or_prop,
                            reason: reason.clone()
                        }
                    };
                }
            }
            BetState::Proposed { local_proposal } => {
                if let Some(reason) = self
                    .check_cancelled(&local_proposal.proposal.payload.inputs)
                    .await?
                {
                    update_bet! { self, bet_id,
                        BetState::Proposed { local_proposal } => BetState::Cancelled {
                            bet_or_prop: BetOrProp::Proposal(local_proposal),
                            reason: reason.clone()
                        }
                    };
                }
            }
            BetState::Offered { bet, .. } => {
                let txid = bet.tx.txid();
                if let Some(height) = self
                    .is_confirmed(txid, bet.joint_output.wallet_descriptor())
                    .await?
                {
                    update_bet! { self, bet_id,
                        BetState::Offered { bet, .. } => BetState::Confirmed { bet, height }
                    };
                }

                let inputs_to_check_for_cancellation = bet
                    .tx
                    .input
                    .iter()
                    .map(|x| x.previous_output)
                    .collect::<Vec<_>>();
                if let Some(reason) = self
                    .check_cancelled(&inputs_to_check_for_cancellation)
                    .await?
                {
                    update_bet! { self, bet_id,
                        BetState::Cancelling { bet_or_prop, .. } => BetState::Cancelled {
                            bet_or_prop,
                            reason: reason.clone()
                        },
                        BetState::Offered { bet, .. } => BetState::Cancelled {
                            bet_or_prop: BetOrProp::Bet(bet),
                            reason: reason.clone()
                        }
                    };
                }
            }
            BetState::Unconfirmed {
                funding_transaction,
                bet,
            } => {
                let txid = funding_transaction.txid();

                if let Some(height) = self
                    .is_confirmed(txid, bet.joint_output.wallet_descriptor())
                    .await?
                {
                    update_bet! { self, bet_id,
                        BetState::Unconfirmed { bet, .. } => BetState::Confirmed { bet, height }
                    };
                    self.wallet
                        .sync(bdk::blockchain::noop_progress(), None)
                        .await?;
                } else {
                    let inputs_to_check_for_cancellation = bet
                        .tx
                        .input
                        .iter()
                        .map(|x| x.previous_output)
                        .collect::<Vec<_>>();
                    if let Some(reason) = self
                        .check_cancelled(&inputs_to_check_for_cancellation)
                        .await?
                    {
                        update_bet! { self, bet_id,
                            BetState::Cancelling { bet_or_prop, .. } => {
                                BetState::Cancelled {
                                    bet_or_prop,
                                    reason: reason.clone()
                                }
                            }
                        };
                    }
                }
            }
            BetState::Confirmed { bet, height: _ } => {
                self.try_get_outcome(bet_id, bet).await?;
            }
            BetState::Claiming { bet, .. } => {
                let has_been_claimed = self
                    .outpoint_exists(bet.outpoint(), bet.joint_output.wallet_descriptor())
                    .await?;
                if has_been_claimed {
                    update_bet! { self, bet_id,
                                 BetState::Claiming { bet, .. } => BetState::Claimed { bet }
                    }
                }
            }
        }
        Ok(())
    }
}
