use bdk::{
    bitcoin::Network,
    blockchain::{esplora::EsploraBlockchainConfig, AnyBlockchainConfig},
};
use std::path::PathBuf;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WalletKeys {
    SeedWordsFile,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WalletKeyOld {
    #[serde(rename = "p2wpkh")]
    P2wpkh,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WalletKey {
    Descriptor {
        external: String,
        internal: Option<String>,
    },
    SeedWordsFile {},
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConfigV0 {
    pub network: Network,
    pub blockchain: AnyBlockchainConfig,
    pub keys: WalletKeys,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case", tag = "version")]
pub enum VersionedConfig {
    #[serde(rename = "1")]
    V1(Config),
}

impl From<ConfigV0> for Config {
    fn from(from: ConfigV0) -> Self {
        let mut psbt_output_dir = PathBuf::new();
        psbt_output_dir.push(&dirs::home_dir().unwrap());
        psbt_output_dir.push("psbts");

        Config {
            network: from.network,
            psbt_output_dir,
            blockchain: from.blockchain,
            wallet_key: WalletKey::SeedWordsFile {},
        }
    }
}

impl From<VersionedConfig> for Config {
    fn from(from: VersionedConfig) -> Self {
        match from {
            VersionedConfig::V1(config) => config,
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    pub network: Network,
    pub psbt_output_dir: PathBuf,
    pub blockchain: AnyBlockchainConfig,
    pub wallet_key: WalletKey,
}

impl Config {
    pub fn default_config(network: Network) -> Config {
        use Network::*;
        let url = match network {
            Bitcoin => "https://mempool.space/api",
            Testnet => "https://blockstream.info/testnet/api",
            Regtest => "http://localhost:3000",
            Signet => unimplemented!("signet not supported yet!"),
        };

        let blockchain = AnyBlockchainConfig::Esplora(EsploraBlockchainConfig {
            concurrency: Some(10),
            stop_gap: 10,
            ..EsploraBlockchainConfig::new(url.into())
        });

        let mut psbt_output_dir = PathBuf::new();
        psbt_output_dir.push(&dirs::home_dir().unwrap());
        psbt_output_dir.push("psbts");

        Config {
            network,
            psbt_output_dir,
            blockchain,
            wallet_key: WalletKey::SeedWordsFile {},
        }
    }
    pub fn into_versioned(self) -> VersionedConfig {
        VersionedConfig::V1(self)
    }
}
