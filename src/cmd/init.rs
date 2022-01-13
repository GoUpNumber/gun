use crate::{
    cmd,
    config::{Config, WalletKey},
};
use anyhow::{anyhow, Context};
use bdk::{
    bitcoin::Network,
    database::MemoryDatabase,
    keys::{
        bip39::{Language, Mnemonic, MnemonicType},
        GeneratableKey, GeneratedKey,
    },
    miniscript::Segwitv0,
    Wallet,
};
use olivia_secp256k1::fun::hex;
use std::{fs, io, path::PathBuf, str::FromStr};
use structopt::StructOpt;

use super::CmdOutput;

pub enum NWords {}

#[derive(Clone, Debug, StructOpt)]
pub struct CommonArgs {
    /// The network name (bitcoin|regtest|testnet)
    #[structopt(long, default_value = "bitcoin", name = "bitcoin|regtest|testnet")]
    network: Network,
}

#[derive(Clone, Debug, StructOpt)]
pub enum InitOpt {
    /// Initialize a wallet using a seedphrase
    Seed {
        #[structopt(flatten)]
        common_args: CommonArgs,
        /// Existing BIP39 seed words file. Use "-" to read words from stdin.
        #[structopt(long, name = "FILE")]
        from_existing: Option<String>,
        #[structopt(long, default_value = "12", name = "[12|24]")]
        /// The number of BIP39 seed words to use
        n_words: usize,
    },
    /// Initialize using a wallet descriptor
    Descriptor {
        #[structopt(flatten)]
        common_args: CommonArgs,
        /// Save unsigned PSBTs to this directory. PSBTs will be saved as `<txid>.psbt`.
        /// You then sign and save the transaction into this directory as <txid>-signed.psbt.
        #[structopt(long, parse(from_os_str))]
        psbt_output_dir: Option<PathBuf>,
        /// Initialize the wallet from a descriptor
        #[structopt(name = "wpkh([AAB893A5/84'/0'/0']xpub66..mSXJj/0/*")]
        external: String,
        /// Optional change descriptor
        #[structopt(name = "wpkh([AAB893A5/84'/0'/0']xpub66...mSXJj/1/*)")]
        internal: Option<String>,
    },
    /// Initialize using an extended public key descriptor.
    ///
    /// $ gun init xpub "[E83E2DB9/84'/0'/0']xpub6...a6" --psbt-output-dir ~/.gun/psbts
    ///
    /// With descriptor in format [masterfingerprint/derivation'/path']xpub.
    /// Unsigned PSBTs will be saved to a --psbt-output-dir for signing (default: $GUNDIR/psbts).
    #[structopt(name = "xpub")]
    XPub {
        #[structopt(flatten)]
        common_args: CommonArgs,
        /// Save unsigned PSBTs to this directory. PSBTs will be saved as `<txid>.psbt`.
        /// You then sign and save the transaction into this directory as <txid>-signed.psbt.
        #[structopt(long, parse(from_os_str))]
        psbt_output_dir: Option<PathBuf>,
        /// Initialize the wallet from a descriptor
        #[structopt(name = "xpub-descriptor")]
        xpub: String,
    },
}

fn create_psbt_dir(
    wallet_dir: &std::path::Path,
    psbt_output_dir: Option<PathBuf>,
) -> anyhow::Result<PathBuf> {
    let psbt_output_dir = match psbt_output_dir {
        Some(psbt_output_dir) => psbt_output_dir,
        None => {
            let mut psbt_output_dir = PathBuf::new();
            psbt_output_dir.push(wallet_dir);
            psbt_output_dir.push("psbts");
            psbt_output_dir
        }
    };
    if !psbt_output_dir.exists() {
        fs::create_dir_all(&psbt_output_dir)
            .with_context(|| format!("Creating PSBT dir {}", psbt_output_dir.display()))?;
    }
    Ok(psbt_output_dir.to_owned())
}

fn create_secret_randomness(wallet_dir: &std::path::Path) -> anyhow::Result<()> {
    let mut random_bytes = [0u8; 64];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut random_bytes);

    let hex_randomness = hex::encode(&random_bytes);
    let mut secret_file = wallet_dir.to_path_buf();
    secret_file.push("secret_protocol_randomness");
    fs::write(secret_file, hex_randomness)?;
    Ok(())
}

pub fn run_init(wallet_dir: &std::path::Path, cmd: InitOpt) -> anyhow::Result<CmdOutput> {
    if wallet_dir.exists() {
        return Err(anyhow!(
            "wallet directory {} already exists -- delete it to create a new wallet",
            wallet_dir.display()
        ));
    }

    std::fs::create_dir(&wallet_dir)?;

    let mut config_file = wallet_dir.to_path_buf();
    config_file.push("config.json");

    let config = match cmd {
        InitOpt::Seed {
            common_args,
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
                    WalletKey::SeedWordsFile {}
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
                    WalletKey::SeedWordsFile {}
                }
            };
            Config {
                wallet_key,
                ..Config::default_config(common_args.network)
            }
        }
        InitOpt::Descriptor {
            common_args,
            psbt_output_dir,
            external,
            internal,
        } => {
            let psbt_dir = create_psbt_dir(wallet_dir, psbt_output_dir)?;
            create_secret_randomness(&wallet_dir)?;
            // Check descriptors are valid
            let _ = Wallet::new_offline(
                &external,
                internal.as_ref(),
                common_args.network,
                MemoryDatabase::default(),
            )?;

            Config {
                wallet_key: WalletKey::Descriptor { external, internal },
                psbt_output_dir: psbt_dir,
                ..Config::default_config(common_args.network)
            }
        }
        InitOpt::XPub {
            common_args,
            psbt_output_dir,
            ref xpub,
        } => {
            let psbt_dir = create_psbt_dir(wallet_dir, psbt_output_dir)?;
            create_secret_randomness(&wallet_dir)?;
            let external = format!("wpkh({}/0/*)", xpub);
            let internal = format!("wpkh({}/1/*)", xpub);

            // Check xpub is valid
            let _ = Wallet::new_offline(
                &external,
                Some(&internal),
                common_args.network,
                MemoryDatabase::default(),
            )?;

            Config {
                wallet_key: WalletKey::Descriptor {
                    external,
                    internal: Some(internal),
                },
                psbt_output_dir: psbt_dir,
                ..Config::default_config(common_args.network)
            }
        }
    };
    fs::write(
        config_file,
        serde_json::to_string_pretty(&config.into_versioned())
            .unwrap()
            .as_bytes(),
    )?;

    Ok(CmdOutput::None)
}
