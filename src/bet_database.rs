use anyhow::anyhow;
use bdk::bitcoin::{Transaction, Txid};
use olivia_core::{OracleEvent, OracleId, OracleInfo};
use olivia_secp256k1::Secp256k1;
use std::{cell::RefCell, collections::HashMap};

use crate::party::{JointOutput, LocalProposal};

pub type BetId = u32;

pub trait BetDatabase {
    fn get_bet(&self, bet_id: BetId) -> anyhow::Result<Option<BetState>>;
    fn take_offer(
        &self,
        bet_id: BetId,
        tx: Transaction,
        vout: u32,
        joint_output: JointOutput,
    ) -> anyhow::Result<()>;

    fn bet_confirmed(&self, bet_id: BetId, height: u32) -> anyhow::Result<()>;

    fn insert_bet(&self, bet: BetState) -> anyhow::Result<BetId>;
    fn offer_taken(&self, bet_id: BetId, tx: Transaction) -> anyhow::Result<()>;

    fn get_oracle_info(
        &self,
        oracle_id: &OracleId,
    ) -> anyhow::Result<Option<OracleInfo<Secp256k1>>>;
    fn insert_oracle_info(&self, oracle_info: OracleInfo<Secp256k1>) -> anyhow::Result<()>;
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum MapKey {
    OracleInfo(OracleId),
    Bet(u32),
    BetId,
}

pub enum MapKeyKind {
    Proposal,
    Offer,
    Id,
}

#[derive(Default)]
pub struct InMemory {
    inner: RefCell<HashMap<MapKey, Box<dyn std::any::Any + 'static>>>,
}

impl BetDatabase for InMemory {
    fn insert_bet(&self, bet: BetState) -> anyhow::Result<BetId> {
        let mut inner = self.inner.borrow_mut();
        let bet_id = {
            let i = inner
                .entry(MapKey::BetId)
                .and_modify(|i| *i.downcast_mut::<BetId>().unwrap() += 1)
                .or_insert(Box::new(BetId::default()));
            *i.downcast_ref::<BetId>().unwrap()
        };
        inner.insert(MapKey::Bet(bet_id), Box::new(bet));
        Ok(bet_id)
    }

    fn get_bet(&self, bet_id: BetId) -> anyhow::Result<Option<BetState>> {
        Ok(self
            .inner
            .borrow()
            .get(&MapKey::Bet(bet_id))
            .map(|boxany| boxany.downcast_ref::<BetState>().unwrap().clone()))
    }

    fn take_offer(
        &self,
        bet_id: BetId,
        tx: Transaction,
        vout: u32,
        joint_output: JointOutput,
    ) -> anyhow::Result<()> {
        let key = MapKey::Bet(bet_id);
        let mut inner = self.inner.borrow_mut();
        let bet_state = inner
            .remove(&key)
            .unwrap()
            .downcast_ref::<BetState>()
            .unwrap()
            .clone();

        match bet_state {
            BetState::Proposed { local_proposal } => {
                let bet = BetState::Unconfirmed {
                    bet: Bet {
                        funding_txid: tx.txid(),
                        oracle_info: local_proposal.oracle_info,
                        oracle_event: local_proposal.oracle_event,
                        vout,
                        joint_output,
                    },
                    funding_transaction: tx,
                };
                inner.insert(key, Box::new(bet));
            }
            _ => panic!("proposal was in wrong state"),
        }
        Ok(())
    }

    // fn list_proposals(&self) -> anyhow::Result<Vec<LocalProposal>> {
    //     Ok(self
    //         .inner
    //         .borrow()
    //         .iter()
    //         .filter_map(|(k, v)| {
    //             if let MapKey::Bet(_) = k {
    //                 if let BetState::Proposed { local_proposal } =
    //                     v.downcast_ref::<BetState>().unwrap().clone()
    //                 {
    //                     Some(local_proposal)
    //                 } else {
    //                     None
    //                 }
    //             } else {
    //                 None
    //             }
    //         })
    //         .collect())
    // }

    fn get_oracle_info(
        &self,
        oracle_id: &OracleId,
    ) -> anyhow::Result<Option<OracleInfo<Secp256k1>>> {
        Ok(self
            .inner
            .borrow()
            .get(&MapKey::OracleInfo(oracle_id.clone()))
            .map(|i| i.downcast_ref::<OracleInfo<Secp256k1>>().unwrap().clone()))
    }

    fn insert_oracle_info(&self, oracle_info: OracleInfo<Secp256k1>) -> anyhow::Result<()> {
        self.inner.borrow_mut().insert(
            MapKey::OracleInfo(oracle_info.id.clone()),
            Box::new(oracle_info),
        );
        Ok(())
    }

    // fn list_bets(&self) -> anyhow::Result<Vec<OfferState>> {
    //     Ok(self
    //        .inner
    //        .borrow()
    //        .iter()
    //        .filter_map(|(k, v)| {
    //            if let MapKey::Offer(_) = k {
    //                Some(v.downcast_ref::<OfferState>().unwrap().clone())
    //            } else {
    //                None
    //            }
    //        })
    //        .collect())
    // }

    fn bet_confirmed(&self, bet_id: BetId, height: u32) -> anyhow::Result<()> {
        let key = MapKey::Bet(bet_id);

        let bet_state = self
            .inner
            .borrow()
            .get(&key)
            .unwrap()
            .downcast_ref::<BetState>()
            .unwrap()
            .clone();

        match bet_state {
            BetState::Unconfirmed { bet, .. }| BetState::Offered { bet }
             => {
                self.inner.borrow_mut().insert(key, Box::new(BetState::Confirmed {
                    bet,
                    height
                }));
            }
            _ => return Err(anyhow!("Tried to register the funding transaction for a proposal that was in the wrong state")),
        }
        Ok(())
    }

    fn offer_taken(&self, bet_id: BetId, funding_transaction: Transaction) -> anyhow::Result<()> {
        let key = MapKey::Bet(bet_id);
        let bet_state = self
            .inner
            .borrow()
            .get(&key)
            .unwrap()
            .downcast_ref::<BetState>()
            .unwrap()
            .clone();

        match bet_state {
            BetState::Offered { bet } => {
                self.inner.borrow_mut().insert(
                    key,
                    Box::new(BetState::Unconfirmed {
                        bet,
                        funding_transaction,
                    }),
                );
            }
            _ => {
                return Err(anyhow!(
                    "Tried to register an offer as taken that has already been taken"
                ))
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Bet {
    pub funding_txid: Txid,
    pub vout: u32,
    pub joint_output: JointOutput,
    pub oracle_info: OracleInfo<Secp256k1>,
    pub oracle_event: OracleEvent<Secp256k1>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum BetState {
    Proposed {
        local_proposal: LocalProposal,
    },
    Offered {
        bet: Bet,
    },
    Unconfirmed {
        bet: Bet,
        funding_transaction: Transaction,
    },
    Confirmed {
        bet: Bet,
        height: u32,
    },
    Outcome {
        bet: Bet,
        height: u32,
        left_won: bool,
        claim_tx: Transaction,
    },
}

// impl MapKey {
//     fn to_bytes(&self) -> Vec<u8> {
//         crate::encode::serialize(self)
//     }
// }

// impl BetDatabase for Tree {
//     fn insert_proposal(&self, local_proposal: LocalProposal) -> anyhow::Result<()> {
//         let key = MapKey::Proposal(local_proposal.proposal.id());
//         self.insert(
//             key.to_bytes(),
//             crate::encode::serialize(&ProposalState::Proposed { local_proposal }),
//         )?;
//         Ok(())
//     }

//     fn get_proposal(&self, proposal_id: ProposalId) -> anyhow::Result<Option<ProposalState>> {
//         let key = MapKey::Proposal(proposal_id);
//         Ok(self
//            .get(key.to_bytes())?
//            .map(|bytes| crate::encode::deserialize(&bytes))
//            .transpose()?)
//     }

//     fn take_offer(
//         &self,
//         proposal_id: ProposalId,
//         offer: Offer,
//         tx: Transaction,
//         joint_output: ExtendedDescriptor,
//     ) -> anyhow::Result<()> {
//         let key = MapKey::Proposal(proposal_id).to_bytes();
//         let proposal_state = self.get_proposal(proposal_id)?.ok_or(anyhow!(
//             "Tried to make an offer to a proposal that no longer exists"
//         ))?;
//         match proposal_state {
//             ProposalState::Proposed { local_proposal } => {
//                 self.insert(
//                     key,
//                     crate::encode::serialize(&ProposalState::Taken {
//                         local_proposal,
//                         offer,
//                         tx,
//                         joint_output
//                     }),
//                 )?;
//             }
//             _ => {
//                 return Err(anyhow!(
//                     "Tried to make an offer to a proposal a second time"
//                 ))
//             }
//         }
//         Ok(())
//     }

//     fn list_proposals(&self) -> anyhow::Result<Vec<ProposalState>> {
//         self.scan_prefix((MapKeyKind::Proposal as u32).to_le_bytes())
//             .values()
//             .map(|res| {
//                 Ok(res.map(|bytes| crate::encode::deserialize::<ProposalState>(&bytes).unwrap())?)
//             })
//             .collect()
//     }

//     fn insert_offer(&self, local_offer: LocalOffer) -> anyhow::Result<()> {
//         let key = MapKey::Offer(local_offer.offer.id()).to_bytes();
//         self.insert(
//             key,
//             crate::encode::serialize(&OfferState::Offered { local_offer }),
//         )?;
//         Ok(())
//     }

//     fn list_offers(&self) -> anyhow::Result<Vec<OfferState>> {
//         self.scan_prefix((MapKeyKind::Offer as u32).to_le_bytes())
//             .values()
//             .map(|res| {
//                 Ok(res.map(|bytes| crate::encode::deserialize::<OfferState>(&bytes).unwrap())?)
//             })
//             .collect()
//     }

//     fn get_oracle_info(
//         &self,
//         oracle_id: &OracleId,
//     ) -> anyhow::Result<Option<OracleInfo<Secp256k1>>> {
//         let key = MapKey::OracleInfo(oracle_id.clone()).to_bytes();
//         Ok(self
//            .get(key)?
//            .map(|bytes| crate::encode::deserialize(&bytes))
//            .transpose()?)
//     }

//     fn insert_oracle_info(&self, oracle_info: OracleInfo<Secp256k1>) -> anyhow::Result<()> {
//         let key = MapKey::OracleInfo(oracle_info.id.clone()).to_bytes();
//         self.insert(key, crate::encode::serialize(&oracle_info))?;
//         Ok(())
//     }

//     fn taken_offer_confirmed(&self, proposalid: ProposalId, tx: Transaction) -> anyhow::Result<()> {
//         todo!()
//     }

//     fn offer_taken(&self, offer_id: OfferId, tx: Transaction) -> anyhow::Result<()> {
//         let key = MapKey::Offer(offer_id).to_bytes();
//         let
//     }
// }
