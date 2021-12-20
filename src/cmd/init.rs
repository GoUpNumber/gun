use crate::{
    cmd,
    config::{Config, WalletKey},
};
use anyhow::{anyhow, Context};
use bdk::{
    bitcoin::Network,
    keys::{
        bip39::{Language, Mnemonic, MnemonicType},
        GeneratableKey, GeneratedKey,
    },
    miniscript::Segwitv0,
};

use std::{fs, io, path::PathBuf, str::FromStr};
use structopt::StructOpt;

use super::CmdOutput;

pub enum NWords {}

#[derive(Clone, Debug, StructOpt)]
pub enum InitOpt {
    /// Initialize a wallet using a seedphrase
    Seed {
        /// The network name (bitcoin|regtest|testnet)
        #[structopt(long, default_value = "bitcoin", name = "bitcoin|regtest|testnet")]
        network: Network,
        /// Existing BIP39 seed words file. Use "-" to read words from stdin.
        #[structopt(long, name = "FILE")]
        from_existing: Option<String>,
        #[structopt(long, default_value = "12", name = "[12|24]")]
        /// The number of BIP39 seed words to use
        n_words: usize,
    },
    /// Initialize using a wallet descriptor
    Descriptor {
        /// The network name (bitcoin|regtest|testnet)
        #[structopt(long, default_value = "bitcoin", name = "bitcoin|regtest|testnet")]
        network: Network,
        /// Initialize the wallet from a descriptor
        #[structopt(name = "wpkh([AAB893A5/84'/0'/0']xpub66...mSXJj")]
        external: String,
        /// Optional change descriptor
        #[structopt(name = "wpkh([AAB893A5/84'/0'/0']xpub66...mSXJj/1/*)")]
        internal: Option<String>,
    },
}

pub fn run_init(wallet_dir: &std::path::Path, cmd: InitOpt) -> anyhow::Result<CmdOutput> {
    if wallet_dir.exists() {
        return Err(anyhow!(
            "wallet directory {} already exists -- delete it to create a new wallet",
            wallet_dir.display()
        ));
    }

    std::fs::create_dir(&wallet_dir)?;

    match cmd {
        InitOpt::Seed {
            network,
            from_existing,
            n_words,
        } => {
            let wallet_key = match from_existing {
                Some(existing_words_file) => {
                    let seed_words = match existing_words_file.as_str() {
                        "-" => {
                            use io::Read;
                            let mut words = String::new();
                            io::stdin().read_to_string(&mut words)?;
                            words
                        }
                        existing_words_file => {
                            let existing_words_file = PathBuf::from_str(existing_words_file)
                                .context("parsing existing seed words file name")?;
                            fs::read_to_string(&existing_words_file).context(format!(
                                "loading existing seed words from {}",
                                existing_words_file.display()
                            ))?
                        }
                    };
                    Mnemonic::validate(&seed_words, Language::English)
                        .context("parsing existing seedwords")?;
                    let sw_file = cmd::get_seed_words_file(wallet_dir);
                    fs::write(sw_file.clone(), seed_words.clone())?;
                    WalletKey::SeedWordsFile
                }
                None => {
                    let n_words = MnemonicType::for_word_count(n_words)?;
                    let seed_words: GeneratedKey<_, Segwitv0> =
                        Mnemonic::generate((n_words, Language::English))
                            .map_err(|_| anyhow!("generating seed phrase failed"))?;
                    let seed_words: String = seed_words.phrase().into();
                    let sw_file = cmd::get_seed_words_file(wallet_dir);
                    fs::write(sw_file.clone(), seed_words.clone())?;
                    eprintln!("Wrote seeds words to {}", sw_file.display());
                    println!("==== BIP39 seed words ====");
                    WalletKey::SeedWordsFile
                }
            };
            let mut config_file = wallet_dir.to_path_buf();
            config_file.push("config.json");

            let config = Config {
                wallet_key: Some(wallet_key),
                ..Config::default_config(network)
            };
            fs::write(
                config_file,
                serde_json::to_string_pretty(&config).unwrap().as_bytes(),
            )?;
        }
        InitOpt::Descriptor {
            network,
            internal,
            external,
        } => {
            todo!();
        }
    };

    Ok(CmdOutput::None)
}
