use crate::{cmd, config::Config, item};
use anyhow::{anyhow, Context};
use bdk::{
    bitcoin::Network,
    keys::{
        bip39::{Language, Mnemonic, MnemonicType},
        GeneratableKey, GeneratedKey,
    },
    miniscript::Segwitv0,
};
use cmd::Cell;
use std::{
    fs,
    io::{self, Read},
    path::PathBuf,
    str::FromStr,
};
use structopt::StructOpt;

use super::CmdOutput;

pub enum NWords {}

#[derive(Clone, Debug, StructOpt)]
pub struct InitOpt {
    /// The network name (bitcoin|regtest|testnet)
    #[structopt(name = "bitcoin|regtest|testnet")]
    network: Network,
    /// Existing BIP39 seed words file. Use "-" to read words from stdin.
    #[structopt(long, name = "FILE")]
    from_existing: Option<String>,
    #[structopt(long, default_value = "12", name = "[12|24]")]
    /// The number of BIP39 seed words to use
    n_words: usize,
}

pub fn run_init(
    wallet_dir: &std::path::Path,
    InitOpt {
        network,
        n_words,
        from_existing,
    }: InitOpt,
) -> anyhow::Result<CmdOutput> {
    if wallet_dir.exists() {
        return Err(anyhow!(
            "wallet directory {} already exists -- delete it to create a new wallet",
            wallet_dir.display()
        ));
    }

    let mut use_pass = false;

    let seed_words = match from_existing {
        Some(existing_words_file) => {
            let words = match existing_words_file.as_str() {
                "-" => {
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
            Mnemonic::validate(&words, Language::English).context("parsing existing seedwords")?;
            words
        }
        None => {
            let n_words = MnemonicType::for_word_count(n_words)?;
            println!("Use bip39 passphrase? (y/n)");
            println!(
                "Note: If given, passphrase will be asked for every command. Enter 'n' to skip"
            );
            let mut answer = String::new();
            io::stdin().read_line(&mut answer)?;
            match answer.trim() {
                "y" => use_pass = true,
                "n" => use_pass = false,
                _ => return Err(anyhow!("Wrong answer, try again")),
            }
            let seed_words: GeneratedKey<_, Segwitv0> =
                Mnemonic::generate((n_words, Language::English))
                    .map_err(|_| anyhow!("generating seed phrase failed"))?;
            seed_words.phrase().into()
        }
    };

    std::fs::create_dir(&wallet_dir)?;

    {
        let mut config_file = wallet_dir.to_path_buf();
        config_file.push("config.json");

        let mut config = Config::default_config(network);
        config.passphrase = use_pass;
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
