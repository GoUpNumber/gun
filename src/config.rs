use bdk::{
    bitcoin::{util::bip32::Fingerprint, Network},
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
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum GunSigner {
    SeedWordsFile {
        #[serde(skip_serializing_if = "Option::is_none")]
        passphrase_fingerprint: Option<Fingerprint>,
    },
    PsbtDir {
        path: PathBuf,
    },
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case", tag = "version")]
pub enum VersionedConfig {
    #[serde(rename = "1")]
    V1(Config),
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
    pub blockchain: AnyBlockchainConfig,
    pub signers: Vec<GunSigner>,
}

impl Config {
    pub fn default_config(network: Network) -> Config {
        use Network::*;
        let url = match network {
            Bitcoin => "https://mempool.space/api",
            Testnet => "https://mempool.space/testnet/api",
            Regtest => "http://localhost:3000",
            Signet => "https://mempool.space/signet/api",
        };

        let blockchain = AnyBlockchainConfig::Esplora(EsploraBlockchainConfig {
            concurrency: Some(10),
            ..EsploraBlockchainConfig::new(url.into(), 10)
        });

        Config {
            network,
            blockchain,
            signers: vec![],
        }
    }
    pub fn into_versioned(self) -> VersionedConfig {
        VersionedConfig::V1(self)
    }

    pub fn blockchain_config(&self) -> &EsploraBlockchainConfig {
        match &self.blockchain {
            AnyBlockchainConfig::Esplora(config) => config,
        }
    }
}
