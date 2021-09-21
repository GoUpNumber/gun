use crate::{
    bet::{Bet, OfferedBet},
    ciphertext::Ciphertext,
    party::LocalProposal,
    OracleInfo,
};
use anyhow::{anyhow, Context};
use bdk::{
    bitcoin::{secp256k1::SecretKey, OutPoint, Txid},
    sled::{
        self,
        transaction::{ConflictableTransactionError, TransactionalTree},
    },
};
use olivia_core::{Attestation, OracleId};
use olivia_secp256k1::Secp256k1;

pub const DB_VERSION: u8 = 0;
pub type BetId = u32;

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum MapKey {
    BetId,
    OracleInfo(OracleId),
    Bet(BetId),
    ClaimTx(Txid),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct VersionedKey {
    pub version: u8,
    pub key: MapKey,
}

impl VersionedKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        crate::encode::serialize(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        crate::encode::deserialize::<VersionedKey>(bytes).unwrap()
    }
}

impl From<MapKey> for VersionedKey {
    fn from(key: MapKey) -> Self {
        VersionedKey {
            version: DB_VERSION,
            key,
        }
    }
}

#[derive(serde::Serialize)]
pub enum KeyKind {
    BetId,
    OracleInfo,
    Bet,
}

impl KeyKind {
    pub fn prefix(&self) -> Vec<u8> {
        crate::encode::serialize(&(DB_VERSION, self))
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state")]
pub enum BetState {
    Proposed {
        local_proposal: LocalProposal,
    },
    Offered {
        bet: OfferedBet,
        encrypted_offer: Ciphertext,
    },
    Confirmed {
        bet: Bet,
        height: Option<u32>,
    },
    Won {
        bet: Bet,
        secret_key: SecretKey,
        attestation: Attestation<Secp256k1>,
    },
    Lost {
        bet: Bet,
        attestation: Attestation<Secp256k1>,
    },
    Claimed {
        bet: Bet,
        txid: Txid,
        height: Option<u32>,
        secret_key: SecretKey,
        attestation: Attestation<Secp256k1>,
    },
    Canceled {
        pre_cancel: BetOrProp,
        bet_spent_vin: u32,
        cancel_txid: Txid,
        cancel_vin: u32,
        height: Option<u32>,
        /// Whether we intend to cancel the bet.
        i_intend_cancel: bool,
    },
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum BetOrProp {
    Bet(Bet),
    Proposal(LocalProposal),
    OfferedBet {
        bet: OfferedBet,
        encrypted_offer: Ciphertext,
    },
}

impl BetOrProp {
    pub fn inputs(&self) -> Vec<OutPoint> {
        match self {
            BetOrProp::Bet(bet)
            | BetOrProp::OfferedBet {
                bet: OfferedBet(bet),
                ..
            } => bet
                .tx()
                .input
                .iter()
                .map(|input| input.previous_output)
                .collect(),
            BetOrProp::Proposal(local_proposal) => local_proposal.proposal.inputs.clone(),
        }
    }
}

impl BetState {
    pub fn name(&self) -> &'static str {
        use BetState::*;
        match self {
            Proposed { .. } => "proposed",
            Offered { .. } => "offered",
            Confirmed { height: None, .. } => "unconfirmed",
            Confirmed {
                height: Some(_), ..
            } => "confirmed",
            Won { .. } => "won",
            Lost { .. } => "lost",
            Claimed { height: None, .. } => "claiming",
            Claimed {
                height: Some(_), ..
            } => "claimed",
            Canceled { height: None, .. } => "canceling",
            Canceled {
                height: Some(_), ..
            } => "canceled",
        }
    }

    pub fn reserved_utxos(&self) -> Vec<OutPoint> {
        use BetState::*;
        match self {
            Proposed { local_proposal } => local_proposal
                .proposal
                .inputs
                .iter()
                .map(Clone::clone)
                .collect(),
            Offered {
                bet: OfferedBet(bet),
                ..
            }
            | Confirmed { bet, .. } => bet
                .my_input_indexes
                .iter()
                .map(|i| bet.tx().input[*i as usize].previous_output)
                .collect(),
            _ => vec![],
        }
    }

    pub fn into_bet_or_prop(self) -> BetOrProp {
        match self {
            BetState::Proposed { local_proposal } => BetOrProp::Proposal(local_proposal),
            BetState::Offered {
                bet,
                encrypted_offer,
            } => BetOrProp::OfferedBet {
                bet,
                encrypted_offer,
            },
            BetState::Canceled { pre_cancel, .. } => pre_cancel,
            BetState::Confirmed { bet, .. }
            | BetState::Won { bet, .. }
            | BetState::Lost { bet, .. }
            | BetState::Claimed { bet, .. } => BetOrProp::Bet(bet),
        }
    }

    pub fn tags_mut(&mut self) -> &mut Vec<String> {
        match self {
            BetState::Proposed { local_proposal }
            | BetState::Canceled {
                pre_cancel: BetOrProp::Proposal(local_proposal),
                ..
            } => &mut local_proposal.tags,
            BetState::Offered {
                bet: OfferedBet(bet),
                ..
            }
            | BetState::Confirmed { bet, .. }
            | BetState::Won { bet, .. }
            | BetState::Lost { bet, .. }
            | BetState::Claimed { bet, .. }
            | BetState::Canceled {
                pre_cancel:
                    BetOrProp::OfferedBet {
                        bet: OfferedBet(bet),
                        ..
                    }
                    | BetOrProp::Bet(bet),
                ..
            } => &mut bet.tags,
        }
    }
}

pub trait Entity: serde::de::DeserializeOwned + Clone + 'static {
    type Key: Clone;
    fn key_kind() -> KeyKind;
    fn deserialize_key(bytes: &[u8]) -> anyhow::Result<Self::Key>;
    fn extract_key(key: MapKey) -> Option<Self::Key>;
    fn to_map_key(key: Self::Key) -> MapKey;
    fn name() -> &'static str;
}

macro_rules! impl_entity {
    ($key_name:ident, $type:ty, $type_name:ident) => {
        impl Entity for $type {
            type Key = $key_name;
            fn deserialize_key(bytes: &[u8]) -> anyhow::Result<Self::Key> {
                let versioned_key = $crate::encode::deserialize::<VersionedKey>(bytes)?;
                if let MapKey::$type_name(inner) = versioned_key.key {
                    Ok(inner)
                } else {
                    Err(anyhow::anyhow!(
                        "Could not deserialize key {}",
                        stringify!($type_name)
                    ))
                }
            }

            fn key_kind() -> KeyKind {
                KeyKind::$type_name
            }

            fn extract_key(key: MapKey) -> Option<Self::Key> {
                if let MapKey::$type_name(key) = key {
                    Some(key)
                } else {
                    None
                }
            }

            fn to_map_key(key: Self::Key) -> MapKey {
                MapKey::$type_name(key)
            }

            fn name() -> &'static str {
                stringify!($type_name)
            }
        }
    };
}

impl_entity!(OracleId, OracleInfo, OracleInfo);
impl_entity!(BetId, BetState, Bet);

pub struct BetDatabase(sled::Tree);

fn insert<O: serde::Serialize>(tree: &sled::Tree, key: MapKey, value: O) -> anyhow::Result<()> {
    tree.insert(
        VersionedKey::from(key).to_bytes(),
        serde_json::to_string(&value).unwrap().into_bytes(),
    )?;
    Ok(())
}

impl BetDatabase {
    pub fn new(tree: sled::Tree) -> Self {
        BetDatabase(tree)
    }

    pub fn insert_bet(&self, bet: BetState) -> anyhow::Result<BetId> {
        use std::convert::TryFrom;
        let i = self
            .0
            .update_and_fetch(
                VersionedKey::from(MapKey::BetId).to_bytes(),
                |prev| match prev {
                    Some(prev) => Some(
                        (u32::from_be_bytes(<[u8; 4]>::try_from(prev).unwrap()) + 1)
                            .to_be_bytes()
                            .to_vec(),
                    ),
                    None => Some(0u32.to_be_bytes().to_vec()),
                },
            )?
            .unwrap();
        let i = u32::from_be_bytes(<[u8; 4]>::try_from(i.to_vec()).unwrap());

        insert(&self.0, MapKey::Bet(i), bet)?;

        Ok(i)
    }

    pub fn currently_used_utxos(&self, ignore: &[BetId]) -> anyhow::Result<Vec<OutPoint>> {
        Ok(self
            .list_entities::<BetState>()
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|(bet_id, _)| !ignore.contains(bet_id))
            .flat_map(|(_, bet)| bet.reserved_utxos())
            .collect())
    }

    pub fn insert_oracle_info(&self, oracle_info: OracleInfo) -> anyhow::Result<()> {
        let key = MapKey::OracleInfo(oracle_info.id.clone());
        insert(&self.0, key, oracle_info)
    }

    pub fn get_entity<T: Entity>(&self, key: T::Key) -> anyhow::Result<Option<T>> {
        Ok(self
            .0
            .get(VersionedKey::from(T::to_map_key(key)).to_bytes())?
            .map(|bytes| serde_json::from_slice(&bytes))
            .transpose()?)
    }

    pub fn remove_entity<T: Entity>(&self, key: T::Key) -> anyhow::Result<Option<T>> {
        Ok(self
            .0
            .remove(VersionedKey::from(T::to_map_key(key)).to_bytes())?
            .map(|bytes| serde_json::from_slice(&bytes))
            .transpose()?)
    }

    pub fn update_bets<F>(&self, bet_ids: &[BetId], f: F) -> anyhow::Result<()>
    where
        F: Fn(BetState, BetId, TxDb) -> anyhow::Result<BetState>,
    {
        self.0
            .transaction(move |db| {
                for bet_id in bet_ids {
                    let key = VersionedKey::from(MapKey::Bet(*bet_id));
                    let key = key.to_bytes();
                    let old_state =
                        db.remove(key.clone())?
                            .ok_or(ConflictableTransactionError::Abort(anyhow!(
                                "bet {} does not exist",
                                bet_id
                            )))?;
                    let old_state = serde_json::from_slice(&old_state[..])
                        .expect("it's in the DB so it should be deserializable");
                    let new_state = f(old_state, *bet_id, TxDb(db))
                        .map_err(ConflictableTransactionError::Abort)?;
                    db.insert(key, serde_json::to_vec(&new_state).unwrap())?;
                }
                Ok(())
            })
            .map_err(|e| match e {
                bdk::sled::transaction::TransactionError::Abort(e) => e,
                bdk::sled::transaction::TransactionError::Storage(e) => e.into(),
            })
    }

    pub fn list_entities<T: Entity>(&self) -> impl Iterator<Item = anyhow::Result<(T::Key, T)>> {
        self.0.scan_prefix(T::key_kind().prefix()).map(|item| {
            let (key, value) = item?;
            Ok((
                T::deserialize_key(&key[..])
                    .with_context(|| format!("Error Deserializing key for {}", T::name()))?,
                serde_json::from_slice(&value[..])
                    .with_context(|| format!("Error Deserialzing {}", T::name()))?,
            ))
        })
    }

    pub fn list_entities_print_error<T: Entity>(&self) -> impl Iterator<Item = (T::Key, T)> {
        self.list_entities().filter_map(|entity| match entity {
            Ok(entity) => Some(entity),
            Err(e) => {
                eprintln!("Error retreiving an {}: {}", T::name(), e);
                None
            }
        })
    }

    pub fn test_new() -> Self {
        BetDatabase::new(
            bdk::sled::Config::new()
                .temporary(true)
                .flush_every_ms(None)
                .open()
                .unwrap()
                .open_tree("test")
                .unwrap(),
        )
    }
}

#[derive(Clone, Copy)]
pub struct TxDb<'a>(&'a TransactionalTree);

impl<'a> TxDb<'a> {
    pub fn get_entity<T: Entity>(&self, key: T::Key) -> anyhow::Result<Option<T>> {
        Ok(self
            .0
            .get(VersionedKey::from(T::to_map_key(key)).to_bytes())?
            .map(|bytes| serde_json::from_slice(&bytes))
            .transpose()?)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn insert_and_list_oracles() {
        let db = BetDatabase::new(
            sled::Config::new()
                .temporary(true)
                .flush_every_ms(None)
                .open()
                .unwrap()
                .open_tree("test")
                .unwrap(),
        );

        let info1 = OracleInfo::test_oracle_info();
        let info2 = {
            let mut info2 = OracleInfo::test_oracle_info();
            info2.id = "oracle2.test".into();
            info2
        };
        db.insert_oracle_info(info1.clone()).unwrap();
        let oracle_list = db
            .list_entities::<OracleInfo>()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(oracle_list, vec![(info1.id.clone(), info1.clone())]);
        db.insert_oracle_info(info2.clone()).unwrap();
        let mut oracle_list = db
            .list_entities::<OracleInfo>()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        oracle_list.sort_by_key(|(id, _)| id.clone());
        assert_eq!(
            oracle_list,
            vec![(info1.id.clone(), info1), (info2.id.clone(), info2)]
        );
    }
}
