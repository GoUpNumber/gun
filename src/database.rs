use crate::{betting::*, elog, keychain::ProtocolSecret, OracleInfo};
use anyhow::{anyhow, Context};
use bdk::{
    bitcoin::OutPoint,
    sled::{
        self,
        transaction::{ConflictableTransactionError, TransactionalTree},
    },
    KeychainKind,
};
use olivia_core::OracleId;

pub const DB_VERSION: u8 = 0;

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum MapKey {
    BetId,
    OracleInfo(OracleId),
    Bet(BetId),
    ProtocolSecret(ProtocolKind),
    Descriptor(KeychainKind),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ProtocolKind {
    Bet,
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
    ProtocolSecret,
    Descriptor,
}

impl KeyKind {
    pub fn prefix(&self) -> Vec<u8> {
        crate::encode::serialize(&(DB_VERSION, self))
    }
}

pub trait Entity: serde::de::DeserializeOwned + Clone + 'static + serde::Serialize {
    type Key: Clone;
    fn key_kind() -> KeyKind;
    fn deserialize_key(bytes: &[u8]) -> anyhow::Result<Self::Key>;
    fn extract_key(key: MapKey) -> Option<Self::Key>;
    fn to_map_key(key: Self::Key) -> MapKey;
    fn name() -> &'static str;
}

macro_rules! impl_entity {
    ($key_name:ty, $type:ty, $type_name:ident) => {
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
impl_entity!(ProtocolKind, ProtocolSecret, ProtocolSecret);
#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct StringDescriptor(pub String);
impl_entity!(KeychainKind, StringDescriptor, Descriptor);

pub struct GunDatabase(sled::Tree);

fn insert<O: serde::Serialize>(tree: &sled::Tree, key: MapKey, value: O) -> anyhow::Result<()> {
    tree.insert(
        VersionedKey::from(key).to_bytes(),
        serde_json::to_string(&value).unwrap().into_bytes(),
    )?;
    Ok(())
}

impl GunDatabase {
    pub fn new(tree: sled::Tree) -> Self {
        GunDatabase(tree)
    }

    pub fn insert_bet(&self, bet: BetState) -> anyhow::Result<BetId> {
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

    pub fn insert_entity<T: Entity>(&self, key: T::Key, entity: T) -> anyhow::Result<()> {
        insert(&self.0, T::to_map_key(key), entity)
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
                    let old_state = db.remove(key.clone())?.ok_or_else(|| {
                        ConflictableTransactionError::Abort(anyhow!(
                            "bet {} does not exist",
                            bet_id
                        ))
                    })?;
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
                elog!(@recoverable_error "Error retreiving an {}: {}", T::name(), e);
                None
            }
        })
    }

    pub fn test_new() -> Self {
        GunDatabase::new(
            bdk::sled::Config::new()
                .temporary(true)
                .flush_every_ms(None)
                .open()
                .unwrap()
                .open_tree("test-gun")
                .unwrap(),
        )
    }

    pub fn safely_set_bet_protocol_secret(&self, new_secret: ProtocolSecret) -> anyhow::Result<()> {
        let in_use: Vec<_> = self
            .list_entities::<BetState>()
            .filter_map(|bet| bet.ok())
            .filter(|(_, state)| state.relies_on_protocol_secret())
            .collect();
        if in_use.is_empty() {
            self.insert_entity(ProtocolKind::Bet, new_secret)?;
            Ok(())
        } else {
            let in_use = in_use
                .into_iter()
                .map(|(bet_id, _)| bet_id.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            Err(anyhow!("Bets {} are using the protocol secret so you can't change it until they're resolved", in_use))
        }
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
        let db = GunDatabase::test_new();
        let info1 = OracleInfo::test_oracle_info();
        let info2 = {
            let mut info2 = OracleInfo::test_oracle_info();
            info2.id = "oracle2.test".into();
            info2
        };
        db.insert_entity(info1.id.clone(), info1.clone()).unwrap();
        let oracle_list = db
            .list_entities::<OracleInfo>()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(oracle_list, vec![(info1.id.clone(), info1.clone())]);
        db.insert_entity(info2.id.clone(), info2.clone()).unwrap();
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
