use crate::{cmd, cmd::Cell, database::ProtocolKind, eitem, keychain::ProtocolSecret, wallet::GunWallet};
use bdk::blockchain::AnyBlockchainConfig;
use std::path::Path;
use structopt::StructOpt;

use super::CmdOutput;

#[derive(StructOpt, Debug, Clone)]
pub enum SetGetUnset<T: core::str::FromStr>
where
    T::Err: core::fmt::Display + core::fmt::Debug,
{
    /// Set the value
    Set { value: T },
    /// Unset the value
    Unset,
    /// Get the value
    Get,
}

#[derive(StructOpt, Debug, Clone)]
pub enum SetGet<T: core::str::FromStr>
where
    T::Err: core::fmt::Display + core::fmt::Debug,
{
    /// Set the value
    Set { value: T },
    /// Get the value
    Get,
}

impl<T: core::str::FromStr> From<SetGet<T>> for SetGetUnset<T>
where
    T::Err: core::fmt::Display + core::fmt::Debug,
{
    fn from(setget: SetGet<T>) -> SetGetUnset<T> {
        match setget {
            SetGet::Set { value } => SetGetUnset::Set { value },
            SetGet::Get => SetGetUnset::Get,
        }
    }
}

#[derive(StructOpt, Debug, Clone)]
#[structopt(rename_all = "snake_case")]
pub enum BlockchainSettings {
    /// Base URL of the esplora service.
    ///
    /// eg. `https://blockstream.info/api/`
    BaseUrl(SetGet<String>),
    /// URL of the proxy to use to make requests to the Esplora server.
    ///
    /// The string should be formatted as: `<protocol>://<user>:<password>@host:<port>`.
    Proxy(SetGetUnset<String>),
    /// How many parallel requests to sent to the esplora service
    Concurrency(SetGetUnset<u8>),
    /// How many inactive addresses to give up scanning after
    StopGap(SetGet<usize>),
}

#[derive(StructOpt, Debug, Clone)]
pub enum ConfigOpt {
    /// configure the esplora blockchain client.
    Blockchain(BlockchainSettings),
    /// Protocol specific configuration options.
    Protocol(Protocol),
}

#[derive(StructOpt, Debug, Clone)]
pub enum Protocol {
    /// The betting protocol
    Bet(BetSettings),
}

#[derive(StructOpt, Debug, Clone)]
pub enum BetSettings {
    /// The protocol secret is used to generate temporary keys used in betting.
    ///
    /// Unlike other configuration options it is stored in the database.
    ProtocolSecret(SetGet<ProtocolSecret>)
}

macro_rules! setgetunset {
    ($setget:expr, $config:ident, $config_path:ident, $config_sub:expr, $prop:ident) => {
        match $setget {
            SetGetUnset::Set { value } => {
                $config_sub.$prop = Some(value);
                cmd::write_config($config_path, $config)?;
                Ok(CmdOutput::None)
            }
            SetGetUnset::Get => Ok(CmdOutput::EmphasisedItem {
                main: (
                    stringify!($prop),
                    Cell::maybe_string($config_sub.$prop.as_ref()),
                ),
                other: vec![],
            }),
            SetGetUnset::Unset => {
                $config_sub.$prop = None;
                cmd::write_config($config_path, $config)?;
                Ok(CmdOutput::None)
            }
        }
    };
}

macro_rules! setget {
    ($setget:expr, $config:ident, $config_path:ident, $config_sub:expr, $prop:ident) => {
        match $setget {
            SetGet::Set { value } => {
                $config_sub.$prop = value;
                cmd::write_config($config_path, $config)?;
                Ok(CmdOutput::None)
            }
            SetGet::Get => Ok(CmdOutput::EmphasisedItem {
                main: (stringify!($prop), Cell::string(&$config_sub.$prop)),
                other: vec![],
            }),
        }
    };
}

pub fn run_config_cmd(
    wallet: &GunWallet,
    config_path: &Path,
    opt: ConfigOpt,
) -> anyhow::Result<CmdOutput> {
    let mut config = cmd::load_config(config_path)?;
    match opt {
        ConfigOpt::Blockchain(prop) => {
            let AnyBlockchainConfig::Esplora(esplora_config) = &mut config.blockchain;
            use BlockchainSettings::*;
            match prop {
                BaseUrl(setget) => setget!(setget, config, config_path, esplora_config, base_url),
                Proxy(setget) => setgetunset!(setget, config, config_path, esplora_config, proxy),
                Concurrency(setget) => {
                    setgetunset!(setget, config, config_path, esplora_config, concurrency)
                }
                StopGap(setget) => setget!(setget, config, config_path, esplora_config, stop_gap),
            }
        }
        ConfigOpt::Protocol(protocol) => {
            match protocol {
                Protocol::Bet(bet_settings) => {
                    match bet_settings {
                        BetSettings::ProtocolSecret(setget) => {
                            let db = wallet.gun_db();
                            match setget {
                                SetGet::Get => Ok(
                                    eitem!( "protocol_secret" => Cell::maybe_string(db.get_entity::<ProtocolSecret>(ProtocolKind::Bet)?)),
                                ),
                                SetGet::Set { value } => {
                                    db.safely_set_bet_protocol_secret(value)?;
                                    Ok(CmdOutput::None)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
