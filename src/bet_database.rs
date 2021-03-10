use anyhow::anyhow;
use bdk::{
    bitcoin::{self, secp256k1::SecretKey, Amount, OutPoint, Transaction, Txid},
    sled::{transaction::ConflictableTransactionError, Tree},
};
use olivia_core::{OracleEvent, OracleId, OracleInfo};
use olivia_secp256k1::Secp256k1;
use serde::de::DeserializeOwned;
use std::{cell::RefCell, collections::HashMap};

use crate::party::{JointOutput, LocalProposal};

pub type BetId = u32;

pub trait BetDatabase {
    fn get_bet(&self, bet_id: BetId) -> anyhow::Result<Option<BetState>>;
    fn insert_bet(&self, bet: BetState) -> anyhow::Result<BetId>;

    fn update_bet<F>(&self, bet_id: BetId, f: F) -> anyhow::Result<()>
    where
        F: Fn(BetState) -> anyhow::Result<BetState>;

    fn get_oracle_info(
        &self,
        oracle_id: &OracleId,
    ) -> anyhow::Result<Option<OracleInfo<Secp256k1>>>;
    fn insert_oracle_info(&self, oracle_info: OracleInfo<Secp256k1>) -> anyhow::Result<()>;

    fn list_bets(&self) -> anyhow::Result<Vec<BetId>>;
    fn add_claim_tx(&self, bets: Vec<BetId>, tx: Transaction) -> anyhow::Result<()>;
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum MapKey {
    BetId,
    OracleInfo(OracleId),
    Bet(u32),
    ClaimTx(Txid),
}

impl MapKey {
    fn to_bytes(&self) -> Vec<u8> {
        crate::encode::serialize(self)
    }
}

#[derive(serde::Serialize)]
pub enum KeyKind {
    BetId,
    OracleInfo,
    Bet,
    ClaimTx,
}

impl KeyKind {
    fn to_bytes(&self) -> Vec<u8> {
        crate::encode::serialize(self)
    }
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

    fn update_bet<F>(&self, bet_id: BetId, f: F) -> anyhow::Result<()>
    where
        F: Fn(BetState) -> anyhow::Result<BetState>,
    {
        let old_state = self
            .get_bet(bet_id)?
            .ok_or(anyhow!("Bet {} does not exist", bet_id))?;
        let new_state = f(old_state)?;
        self.inner
            .borrow_mut()
            .insert(MapKey::Bet(bet_id), Box::new(new_state));
        Ok(())
    }

    fn list_bets(&self) -> anyhow::Result<Vec<BetId>> {
        Ok(self
            .inner
            .borrow()
            .keys()
            .filter_map(|key| match key {
                MapKey::Bet(bet_id) => Some(*bet_id),
                _ => None,
            })
            .collect())
    }

    fn add_claim_tx(&self, bets: Vec<BetId>, tx: Transaction) -> anyhow::Result<()> {
        self.inner
            .borrow_mut()
            .insert(MapKey::ClaimTx(tx.txid()), Box::new(Claim { bets, tx }));
        Ok(())
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Claim {
    pub bets: Vec<BetId>,
    pub tx: Transaction,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Bet {
    pub outpoint: OutPoint,
    pub joint_output: JointOutput,
    pub oracle_info: OracleInfo<Secp256k1>,
    pub oracle_event: OracleEvent<Secp256k1>,
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
    pub value: Amount,
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
        has_broadcast: bool,
    },
    Confirmed {
        bet: Bet,
        height: u32,
    },
    Won {
        bet: Bet,
        secret_key: SecretKey,
    },
    Lost {
        bet: Bet,
    },
}

fn get<O: DeserializeOwned>(tree: &Tree, key: MapKey) -> anyhow::Result<Option<O>> {
    Ok(tree
        .get(key.to_bytes())?
        .map(|bytes| crate::encode::deserialize(&bytes))
        .transpose()?)
}

fn insert<O: serde::Serialize>(tree: &Tree, key: MapKey, value: O) -> anyhow::Result<()> {
    tree.insert(key.to_bytes(), crate::encode::serialize(&value))?;
    Ok(())
}

impl BetDatabase for Tree {
    fn get_bet(&self, bet_id: BetId) -> anyhow::Result<Option<BetState>> {
        get(self, MapKey::Bet(bet_id))
    }

    fn insert_bet(&self, bet: BetState) -> anyhow::Result<BetId> {
        use std::convert::TryFrom;
        let i = self
            .update_and_fetch(MapKey::BetId.to_bytes(), |prev| match prev {
                Some(prev) => Some(
                    (u32::from_be_bytes(<[u8; 4]>::try_from(prev).unwrap()) + 1)
                        .to_be_bytes()
                        .to_vec(),
                ),
                None => Some(0u32.to_be_bytes().to_vec()),
            })?
            .unwrap();
        let i = u32::from_be_bytes(<[u8; 4]>::try_from(i.to_vec()).unwrap());

        insert(self, MapKey::Bet(i), bet)?;

        Ok(i)
    }

    fn get_oracle_info(
        &self,
        oracle_id: &OracleId,
    ) -> anyhow::Result<Option<OracleInfo<Secp256k1>>> {
        let key = MapKey::OracleInfo(oracle_id.clone());
        get(self, key)
    }

    fn insert_oracle_info(&self, oracle_info: OracleInfo<Secp256k1>) -> anyhow::Result<()> {
        let key = MapKey::OracleInfo(oracle_info.id.clone());
        insert(self, key, oracle_info)
    }

    fn update_bet<F>(&self, bet_id: BetId, f: F) -> anyhow::Result<()>
    where
        F: Fn(BetState) -> anyhow::Result<BetState>,
    {
        let key = MapKey::Bet(bet_id);

        self.transaction(move |db| {
            let key = key.to_bytes();
            let old_state = db
                .remove(key.clone())?
                .ok_or(ConflictableTransactionError::Abort(anyhow!(
                    "bet {} does not exist",
                    bet_id
                )))?;
            let old_state = crate::encode::deserialize(&old_state)
                .expect("it's in the DB so it should be deserializable");
            let new_state = f(old_state).map_err(ConflictableTransactionError::Abort)?;
            db.insert(key, crate::encode::serialize(&new_state))?;
            Ok(())
        })
        .map_err(|e| match e {
            bdk::sled::transaction::TransactionError::Abort(e) => e,
            bdk::sled::transaction::TransactionError::Storage(e) => e.into(),
        })
    }

    fn list_bets(&self) -> anyhow::Result<Vec<BetId>> {
        Ok(self
            .scan_prefix(KeyKind::BetId.to_bytes())
            .keys()
            .map(|key| crate::encode::deserialize::<BetId>(key.unwrap().as_ref()).unwrap())
            .collect())
    }

    fn add_claim_tx(&self, bets: Vec<BetId>, tx: Transaction) -> anyhow::Result<()> {
        insert(self, MapKey::ClaimTx(tx.txid()), Claim { bets, tx })
    }
}
