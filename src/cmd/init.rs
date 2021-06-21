use crate::{cmd, config::Config, item};
use anyhow::{anyhow, Context};
use bdk::{
    bitcoin::Network,
    keys::{GeneratableKey, GeneratedKey},
};
use bip39::{Language, Mnemonic, MnemonicType};
use cmd::Cell;
use miniscript::Segwitv0;
use std::{fs, path::PathBuf};
use structopt::StructOpt;

use super::CmdOutput;

pub enum NWords {}

#[derive(Clone, Debug, StructOpt)]
pub struct InitOpt {
    /// The network name (bitcoin|regtest|testnet)
    network: Network,
    /// Existing BIP39 seed words file
    #[structopt(long, name = "FILE")]
    from_existing: Option<PathBuf>,
    #[structopt(long, default_value = "12", name = "[12|24]")]
    /// The number of BIP39 seed words to use
    n_words: usize,
}

pub fn run_init(
    wallet_dir: &PathBuf,
    InitOpt {
        network,
        n_words,
        from_existing,
    }: InitOpt,
) -> anyhow::Result<CmdOutput> {
    let seed_words = match from_existing {
        Some(existing_words_file) => {
            let seed_words = fs::read_to_string(&existing_words_file).context(format!(
                "loading existing seed words from {}",
                existing_words_file.display()
            ))?;
            Mnemonic::validate(&seed_words, Language::English)
                .context("parsing existing seedwords")?;
            seed_words
        }
        None => {
            let n_words = MnemonicType::for_word_count(n_words)?;
            let seed_words: GeneratedKey<_, Segwitv0> =
                Mnemonic::generate((n_words, Language::English))
                    .map_err(|_| anyhow!("generating seed phrase failed"))?;
            seed_words.phrase().into()
        }
    };

    if wallet_dir.exists() {
        return Err(anyhow!(
            "wallet directory {} already exists -- delete it to create a new wallet",
            wallet_dir.as_path().display()
        ));
    }

    std::fs::create_dir(&wallet_dir)?;

    {
        let mut config_file = wallet_dir.clone();
        config_file.push("config.json");

        let config = Config::default_config(network);
        fs::write(
            config_file,
            serde_json::to_string_pretty(&config).unwrap().as_bytes(),
        )?;
    }

    let sw_file = cmd::get_seed_words_file(wallet_dir);

    fs::write(sw_file.clone(), seed_words.clone())?;

    eprintln!("Wrote seeds words to {}", sw_file.display());
    println!("==== BIP39 seed words ====");

    Ok(item! { "seed_words" => Cell::String(seed_words)})
}
