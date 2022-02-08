use crate::{
    bip85::get_bip85_bytes,
    cmd::{self},
    config::{Config, GunSigner},
    database::GunDatabase,
    keychain::ProtocolSecret,
};
use anyhow::{anyhow, Context};
use bdk::{
    bitcoin::{secp256k1::Secp256k1, util::bip32::ExtendedPrivKey, Network},
    database::MemoryDatabase,
    keys::{
        bip39::{Language, Mnemonic, WordCount},
        GeneratableKey, GeneratedKey,
    },
    miniscript::Segwitv0,
    sled, KeychainKind, Wallet,
};
use miniscript::{Descriptor, DescriptorPublicKey, TranslatePk1};
use olivia_secp256k1::fun::hex;
use serde::Deserialize;
use std::{fs, io, path::PathBuf, str::FromStr};
use structopt::StructOpt;

use super::CmdOutput;

pub enum NWords {}

#[derive(Clone, Debug, StructOpt)]
pub struct CommonArgs {
    /// The network name
    #[structopt(
        long,
        default_value = "bitcoin",
        name = "bitcoin|regtest|testnet|signet"
    )]
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
        /// Wallet has BIP39 passphrase
        #[structopt(long)]
        use_passphrase: bool,
    },
    /// Initialize using a output descriptor
    ///
    /// This option is intended for people who know what they are doing!
    Descriptor {
        #[structopt(flatten)]
        common_args: CommonArgs,
        /// Save unsigned PSBTs to this directory. PSBTs will be saved as `<txid>.psbt`.
        /// You then sign and save the transaction into this directory as <txid>-signed.psbt.
        /// If this is left unset the wallet will be watch-only.
        #[structopt(long, parse(from_os_str))]
        psbt_signer_dir: Option<PathBuf>,
        /// The external descriptor for the wallet
        #[structopt(name = "external-descriptor")]
        external: String,
        /// Optional internal (change) descriptor
        #[structopt(name = "internal-descriptor")]
        internal: Option<String>,
    },
    /// Initialize using an extended public key descriptor.
    ///
    /// The descriptor must be in [masterfingerprint/hardened'/derivation'/path']xpub format e.g.
    ///
    /// $ gun init xpub "[E83E2DB9/84'/0'/0']xpub66...mSXJj"
    #[structopt(name = "xpub")]
    XPub {
        #[structopt(flatten)]
        common_args: CommonArgs,
        /// Save unsigned PSBTs to this directory. PSBTs will be saved as `<txid>.psbt`.
        /// You then sign and save the transaction into this directory as <txid>-signed.psbt.
        /// If this is left unset the wallet will be watch-only.
        #[structopt(long, parse(from_os_str))]
        psbt_signer_dir: Option<PathBuf>,
        /// the xpub descriptor
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
        /// Import entropy from deterministic entropy file.
        /// On Coldcard: Advanced -> Derive Entropy -> 64-bytes hex.
        /// Enter index 330 and press 1 to export to SD.
        /// Gun will use entropy from drv-hex-idx330.txt.
        /// This is necessary for gun to be able to execute protocols which need auxiliary keys (like gun bet).
        #[structopt(long)]
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

pub fn run_init(wallet_dir: &std::path::Path, cmd: InitOpt) -> anyhow::Result<CmdOutput> {
    if wallet_dir.exists() {
        return Err(anyhow!(
            "wallet directory {} already exists -- delete it to create a new wallet",
            wallet_dir.display()
        ));
    }

    std::fs::create_dir(&wallet_dir)?;

    let config_file = wallet_dir.join("config.json");

    let (config, protocol_secret) = match cmd {
        InitOpt::Seed {
            common_args,
            from_existing,
            n_words,
            use_passphrase,
        } => {
            let (sw_file, seed_words) = match from_existing {
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
                    (sw_file, seed_words)
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
                    (sw_file, seed_words)
                }
            };

            let mnemonic = Mnemonic::parse(&seed_words).map_err(|e| {
                anyhow!(
                    "parsing seed phrase in '{}' failed: {}",
                    sw_file.as_path().display(),
                    e
                )
            })?;

            let passphrase = if use_passphrase {
                eprintln!("Warning: by using a passphrase you are mutating the secret derived from your seed words. \
                           If you lose or forget your seedphrase, you will lose access to your funds.");
                loop {
                    let passphrase =
                        rpassword::prompt_password_stderr("Please enter your wallet passphrase: ")?;
                    let passphrase_confirmation = rpassword::prompt_password_stderr(
                        "Please confirm your wallet passphrase: ",
                    )?;
                    if !passphrase.eq(&passphrase_confirmation) {
                        eprintln!("Mismatching passphrases. Try again.\n")
                    } else {
                        break passphrase;
                    }
                }
            } else {
                "".to_string()
            };

            let seed_bytes = mnemonic.to_seed(passphrase);
            let xpriv = ExtendedPrivKey::new_master(common_args.network, &seed_bytes).unwrap();

            let secp = Secp256k1::signing_only();
            let bip85_bytes: [u8; 64] = get_bip85_bytes::<64>(xpriv, 330, &secp);

            let master_fingerprint = xpriv.fingerprint(&secp);

            let temp_wallet = Wallet::new_offline(
                bdk::template::Bip84(xpriv, bdk::KeychainKind::External),
                Some(bdk::template::Bip84(xpriv, bdk::KeychainKind::Internal)),
                common_args.network,
                MemoryDatabase::new(),
            )
            .context("Initializing wallet with xpriv derived from seed phrase")?;

            let signers = vec![GunSigner::SeedWordsFile {
                file_path: sw_file,
                passphrase_fingerprint: if use_passphrase {
                    Some(master_fingerprint)
                } else {
                    None
                },
            }];

            let external = temp_wallet
                .get_descriptor_for_keychain(KeychainKind::External)
                .to_string();
            let internal = temp_wallet
                .get_descriptor_for_keychain(KeychainKind::Internal)
                .to_string();
            (
                Config {
                    descriptor_external: external.clone(),
                    descriptor_internal: Some(internal),
                    signers,
                    ..Config::default_config(common_args.network, external)
                },
                Some(bip85_bytes),
            )
        }
        InitOpt::Descriptor {
            common_args,
            psbt_signer_dir,
            external,
            internal,
        } => {
            // Check descriptors are valid
            let _ = Wallet::new_offline(
                &external,
                internal.as_ref(),
                common_args.network,
                MemoryDatabase::default(),
            )?;

            let signers = match psbt_signer_dir {
                Some(path) => {
                    vec![GunSigner::PsbtDir { path }]
                }
                None => {
                    vec![]
                }
            };

            (
                Config {
                    descriptor_external: external.clone(),
                    descriptor_internal: internal,
                    signers,
                    ..Config::default_config(common_args.network, external)
                },
                None,
            )
        }
        InitOpt::XPub {
            common_args,
            psbt_signer_dir,
            ref xpub,
        } => {
            let external = format!("wpkh({}/0/*)", xpub);
            let internal = format!("wpkh({}/1/*)", xpub);

            // Check xpub is valid
            let _ = Wallet::new_offline(
                &external,
                Some(&internal),
                common_args.network,
                MemoryDatabase::default(),
            )?;

            let signers = match psbt_signer_dir {
                Some(path) => vec![GunSigner::PsbtDir { path }],
                None => vec![],
            };

            (
                Config {
                    descriptor_external: external.clone(),
                    descriptor_internal: Some(internal),
                    signers,
                    ..Config::default_config(common_args.network, external)
                },
                None,
            )
        }
        InitOpt::Coldcard {
            common_args,
            coldcard_sd_dir,
            import_entropy,
        } => {
            let bip85_bytes = if import_entropy {
                let entropy_file = coldcard_sd_dir.join("drv-hex-idx330.txt");
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

                let hex_vec = hex::decode(hex_entropy).with_context(|| {
                    format!("importing entropy from {}", entropy_file.display())
                })?;
                if hex_vec.len() != 64 {
                    return Err(anyhow!("entropy in {} wasn't the right length. We expected 64 bytes of hex but got {}", entropy_file.display(), hex_vec.len()));
                }
                let mut bip85_bytes = [0u8; 64];
                bip85_bytes.copy_from_slice(&hex_vec[..]);
                Some(bip85_bytes)
            } else {
                None
            };

            let wallet_export_file = coldcard_sd_dir.join("coldcard-export.json");
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

            let external = set_network(
                &format!(
                    "wpkh([{}/84'/0'/0']{}/0/*)",
                    &wallet_export.xfp, &wallet_export.bip84.xpub
                ),
                common_args.network,
            )
            .context("generating external descriptor")?;
            let internal = set_network(
                &format!(
                    "wpkh([{}/84'/0'/0']{}/1/*)",
                    &wallet_export.xfp, &wallet_export.bip84.xpub
                ),
                common_args.network,
            )
            .context("generating internal descriptor")?;
            let signers = vec![GunSigner::PsbtDir {
                path: coldcard_sd_dir,
            }];

            (
                Config {
                    descriptor_external: external.clone(),
                    descriptor_internal: Some(internal),
                    signers,
                    ..Config::default_config(common_args.network, external)
                },
                bip85_bytes,
            )
        }
    };

    if let Some(protocol_secret) = protocol_secret {
        let gun_db = GunDatabase::new(
            sled::open(wallet_dir.join("database.sled").to_str().unwrap())?.open_tree("gun")?,
        );
        gun_db.insert_entity((), ProtocolSecret::Bytes(protocol_secret))?;
    }

    fs::write(
        config_file,
        serde_json::to_string_pretty(&config.into_versioned())
            .unwrap()
            .as_bytes(),
    )?;

    Ok(CmdOutput::None)
}

fn set_network(descriptor: &str, network: Network) -> anyhow::Result<String> {
    let descriptor = Descriptor::<DescriptorPublicKey>::from_str(descriptor)?;
    Ok(descriptor
        .translate_pk1_infallible(|pk| {
            let mut pk = pk.clone();
            if let DescriptorPublicKey::XPub(xpub) = &mut pk {
                xpub.xkey.network = network;
            }
            pk
        })
        .to_string())
}
