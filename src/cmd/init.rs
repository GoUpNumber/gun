use crate::config::Config;
use anyhow::anyhow;
use bdk::{
    bitcoin::Network,
    keys::{GeneratableKey, GeneratedKey},
};
use bip39::{Language, Mnemonic, MnemonicType};
use miniscript::Segwitv0;
use std::{fs, path::PathBuf};

pub fn init(wallet_dir: PathBuf, network: Network) -> anyhow::Result<PathBuf> {
    if wallet_dir.exists() {
        return Err(anyhow!(
            "wallet directory {} already exists",
            wallet_dir.as_path().display()
        ));
    }

    let mut seed_words_file = wallet_dir.clone();
    seed_words_file.push("seed.txt");

    std::fs::create_dir(&wallet_dir)?;

    {
        let mut config_file = wallet_dir.clone();
        config_file.push("config.json");

        let config = Config::default_config(network);
        fs::write(
            config_file,
            serde_json::to_string(&config).unwrap().as_bytes(),
        )?;
    }

    let seed_words: GeneratedKey<_, Segwitv0> =
        Mnemonic::generate((MnemonicType::Words12, Language::English))
            .map_err(|_| anyhow!("generating seed phrase failed"))?;
    let seed_words = &*seed_words;

    fs::write(seed_words_file.clone(), seed_words.phrase())?;

    Ok(seed_words_file)
}
