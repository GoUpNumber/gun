use crate::{
    cmd,
    config::{Config, WalletKey},
};
use anyhow::{anyhow, Context};
use bdk::{
    bitcoin::Network,
    database::MemoryDatabase,
    keys::{
        bip39::{Language, Mnemonic, WordCount},
        GeneratableKey, GeneratedKey,
    },
    miniscript::Segwitv0,
    Wallet,
};
use olivia_secp256k1::fun::hex;
use serde::Deserialize;
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
    /// Initialize using a Coldcard SD card path.
    ///
    /// Requires a `coldcard-export.json` in this directory.
    /// On Coldcard: Advanced -> MicroSD Card -> Export Wallet -> Generic JSON
    /// Unsigned PSBTs will be saved to this SD card path, and read once signed.
    Coldcard {
        #[structopt(flatten)]
        common_args: CommonArgs,
        /// Coldcard SD card directory. PSBTs will be saved, signed, and loaded here.
        #[structopt(parse(from_os_str))]
        coldcard_sd_dir: PathBuf,
        /// Instruct gun to use secret randomness from an exported deterministic entropy file.
        /// On Coldcard: Advanced -> Derive Entropy -> 64-bytes hex.
        /// Enter index 330 and press 1 to export to SD.
        /// Gun will use entropy from drv-hex-idx330.txt for secret randomness
        /// which means you may be able to recover funds engaged in protocols if you lose your gun database.
        #[structopt(long, short)]
        import_entropy: bool,
    },
}

#[derive(Deserialize)]
struct WalletExport {
    xfp: String,
    bip84: BIP84Export,
}

#[derive(Deserialize)]
struct BIP84Export {
    xpub: String,
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
                    Mnemonic::parse(&seed_words).context("parsing existing seedwords")?;
                    let sw_file = cmd::get_seed_words_file(wallet_dir);
                    fs::write(sw_file.clone(), seed_words.clone())?;
                    WalletKey::SeedWordsFile {}
                }
                None => {
                    let seed_words: GeneratedKey<_, Segwitv0> = Mnemonic::generate((
                        match n_words {
                            12 => WordCount::Words12,
                            24 => WordCount::Words24,
                            _ => return Err(anyhow!("Only 12 or 24 words are supported")),
                        },
                        Language::English,
                    ))
                    .context("generating seed phrase failed")?;
                    let seed_words: String = seed_words.word_iter().collect::<Vec<_>>().join(" ");
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
        InitOpt::Coldcard {
            common_args,
            coldcard_sd_dir,
            import_entropy,
        } => {
            if !import_entropy {
                create_secret_randomness(wallet_dir)?;
            } else {
                let mut entropy_file = coldcard_sd_dir.to_path_buf();
                entropy_file.push("drv-hex-idx330.txt");
                let contents = match fs::read_to_string(entropy_file.clone()) {
                    Ok(contents) => contents,
                    Err(e) => {
                        return Err(anyhow!(
                            "Could not find entropy export {}.\n{}",
                            entropy_file.display(),
                            e
                        ))
                    }
                };
                let hex_entropy = contents
                    .lines()
                    .nth(1)
                    .ok_or(anyhow!("Unable to read second line from entropy file"))?;

                // Validate hex by decoding
                if let Err(e) = hex::decode(hex_entropy) {
                    return Err(anyhow!(
                        "Unable to decode hex from entropy file.\n{} {}",
                        e,
                        hex_entropy
                    ));
                }

                let mut secret_file = wallet_dir.to_path_buf();
                secret_file.push("secret_protocol_randomness");
                fs::write(secret_file, hex_entropy)?;
            };

            let mut wallet_export_file = coldcard_sd_dir.clone();
            wallet_export_file.push("coldcard-export.json");
            let wallet_export_str = match fs::read_to_string(wallet_export_file.clone()) {
                Ok(contents) => contents,
                Err(e) => {
                    return Err(anyhow!(
                        "Could not read {}.\n{}",
                        wallet_export_file.display(),
                        e
                    ))
                }
            };
            let wallet_export = serde_json::from_str::<WalletExport>(&wallet_export_str)?;

            let external = format!(
                "wpkh([{}/84'/0'/0']{}/0/*)",
                &wallet_export.xfp, &wallet_export.bip84.xpub
            );
            let internal = format!(
                "wpkh([{}/84'/0'/0']{}/1/*)",
                &wallet_export.xfp, &wallet_export.bip84.xpub
            );

            Config {
                wallet_key: WalletKey::Descriptor {
                    external,
                    internal: Some(internal),
                },
                psbt_output_dir: coldcard_sd_dir,
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
