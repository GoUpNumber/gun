use crate::{
    cmd,
    config::{Config, WalletKey},
};
use anyhow::{anyhow, Context};
use bdk::{
    bitcoin::{util::bip32::ExtendedPubKey, Network},
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
    /// Initialize the wallet from an BIP32 xpub
    #[structopt(long)]
    xpub: Option<ExtendedPubKey>,
    /// SD Card path for offline signing
    #[structopt(long, parse(from_os_str))]
    coldcard_sd_path: Option<PathBuf>,
}

pub fn run_init(
    wallet_dir: &std::path::Path,
    InitOpt {
        network,
        n_words,
        from_existing,
        xpub,
        coldcard_sd_path,
    }: InitOpt,
) -> anyhow::Result<CmdOutput> {
    if wallet_dir.exists() {
        return Err(anyhow!(
            "wallet directory {} already exists -- delete it to create a new wallet",
            wallet_dir.display()
        ));
    }

    std::fs::create_dir(&wallet_dir)?;

    let wallet_key = match (from_existing, xpub) {
        (Some(existing_words_file), None) => {
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
        (None, Some(xpub)) => WalletKey::XPub {
            xpub,
            fingerprint: todo!(),
        },
        (None, None) => {
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
        _ => return Err(anyhow!("invalid combination of key source options")),
    };

    {
        let mut config_file = wallet_dir.to_path_buf();
        config_file.push("config.json");

        let config = Config {
            wallet_key: Some(wallet_key),
            coldcard_sd_path: coldcard_sd_path,
            ..Config::default_config(network)
        };
        fs::write(
            config_file,
            serde_json::to_string_pretty(&config).unwrap().as_bytes(),
        )?;
    }

    Ok(CmdOutput::None)
}
