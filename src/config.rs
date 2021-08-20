use bdk::{
    bitcoin::Network,
    blockchain::{esplora::EsploraBlockchainConfig, AnyBlockchainConfig},
};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WalletKeys {
    SeedWordsFile,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WalletKind {
    #[serde(rename = "p2wpkh")]
    P2wpkh,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    pub network: Network,
    pub blockchain: AnyBlockchainConfig,
    pub kind: WalletKind,
    pub keys: WalletKeys,
}

impl Config {
    pub fn default_config(network: Network) -> Config {
        use Network::*;
        let concurrency = Some(4);
        let blockchain = match network {
            Bitcoin => AnyBlockchainConfig::Esplora(EsploraBlockchainConfig {
                base_url: "https://mempool.space/api".to_string(),
                concurrency,
                stop_gap: 10,
            }),
            Testnet => AnyBlockchainConfig::Esplora(EsploraBlockchainConfig {
                base_url: "https://blockstream.info/testnet/api".to_string(),
                concurrency,
                stop_gap: 10,
            }),
            Regtest => AnyBlockchainConfig::Esplora(EsploraBlockchainConfig {
                base_url: "http://localhost:3000".to_string(),
                concurrency,
                stop_gap: 10,
            }),
            Signet => unimplemented!("signet not supported yet!"),
        };

        Config {
            network,
            blockchain,
            kind: WalletKind::P2wpkh,
            keys: WalletKeys::SeedWordsFile,
        }
    }
}
