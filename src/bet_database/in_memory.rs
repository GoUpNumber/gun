use anyhow::{anyhow};
use bdk::{
    bitcoin::{Transaction},
};
use olivia_core::{OracleId, OracleInfo};
use olivia_secp256k1::Secp256k1;
use std::{cell::RefCell, collections::HashMap};
use super::*;

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

    fn update_bet<F,R>(&self, bet_id: BetId, f: F) -> anyhow::Result<R>
    where
        F: Fn(BetState) -> anyhow::Result<(BetState,R)>,
    {
        let old_state = self
            .get_bet(bet_id)?
        .ok_or(anyhow!("Bet {} does not exist", bet_id))?;
        let (new_state, return_val) = f(old_state)?;
        self.inner
            .borrow_mut()
            .insert(MapKey::Bet(bet_id), Box::new(new_state));
        Ok(return_val)
    }

    fn add_claim_tx(&self, bets: Vec<BetId>, tx: Transaction) -> anyhow::Result<()> {
        self.inner
            .borrow_mut()
            .insert(MapKey::ClaimTx(tx.txid()), Box::new(Claim { bets, tx }));
        Ok(())
    }

    fn list_entities<T: Entity>(&self) -> Box<dyn Iterator<Item=anyhow::Result<(T::Key, T)>>> {
        Box::new(self
                      .inner
                      .borrow()
                      .into_iter()
                      .filter_map(|(key, value)| T::extract_key(key.clone()).map(|key| Ok((key, value.downcast_ref::<T>().unwrap().clone())))))
    }
}
