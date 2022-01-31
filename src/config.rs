use crate::hex;
use anyhow::{anyhow, Context};
use bdk::{
    bitcoin::{
        secp256k1::Secp256k1,
        util::bip32::{ExtendedPrivKey, Fingerprint},
        Network,
    },
    blockchain::{esplora::EsploraBlockchainConfig, AnyBlockchainConfig},
    database::MemoryDatabase,
    keys::bip39::Mnemonic,
    KeychainKind, Wallet,
};
use std::{fs, path::PathBuf};

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
        file_path: PathBuf,
        has_passphrase: bool,
        master_fingerprint: Fingerprint,
    },
    PsbtSdCard {
        psbt_signer_dir: PathBuf,
    },
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DerivationBip {
    Bip84,
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

impl ConfigV0 {
    pub fn into_v1(self, wallet_dir: &std::path::Path) -> anyhow::Result<Config> {
        let old_seed_words_file = wallet_dir.join("seed.txt");

        let seed_words = fs::read_to_string(old_seed_words_file.clone()).context(format!(
            "loading existing seed words from {}",
            old_seed_words_file.display()
        ))?;

        let mnemonic = Mnemonic::parse(&seed_words).map_err(|e| {
            anyhow!(
                "parsing seed phrase in '{}' failed: {}",
                old_seed_words_file.as_path().display(),
                e
            )
        })?;

        let seed_bytes = mnemonic.to_seed("");
        let mut secret_file = wallet_dir.to_path_buf();
        secret_file.push("secret_protocol_randomness");
        // Create secret randomness from seed.
        if !secret_file.exists() {
            let hex_seed_bytes = hex::encode(&seed_bytes);
            fs::write(secret_file, hex_seed_bytes)?;
        };

        let xpriv = ExtendedPrivKey::new_master(self.network, &seed_bytes).unwrap();
        let secp = Secp256k1::signing_only();

        let signers = vec![GunSigner::SeedWordsFile {
            file_path: old_seed_words_file,
            has_passphrase: false,
            master_fingerprint: xpriv.fingerprint(&secp),
        }];

        let temp_wallet = Wallet::new_offline(
            bdk::template::Bip84(xpriv, bdk::KeychainKind::External),
            Some(bdk::template::Bip84(xpriv, bdk::KeychainKind::Internal)),
            self.network,
            MemoryDatabase::new(),
        )
        .context("Initializing wallet with xpriv derived from seed phrase")?;

        Ok(Config {
            network: self.network,
            blockchain: self.blockchain,
            descriptor_external: temp_wallet
                .get_descriptor_for_keychain(KeychainKind::External)
                .to_string(),
            descriptor_internal: Some(
                temp_wallet
                    .get_descriptor_for_keychain(KeychainKind::Internal)
                    .to_string(),
            ),
            signers: signers,
        })
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
    pub blockchain: AnyBlockchainConfig,
    pub descriptor_external: String,
    pub descriptor_internal: Option<String>,
    pub signers: Vec<GunSigner>,
}

impl Config {
    pub fn default_config(network: Network, descriptor_external: String) -> Config {
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
            descriptor_external,
            descriptor_internal: None,
            signers: vec![],
        }
    }
    pub fn into_versioned(self) -> VersionedConfig {
        VersionedConfig::V1(self)
    }
}
