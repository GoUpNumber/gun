use crate::{
    bip85::get_bip85_bytes,
    cmd::{self},
    config::{Config, GunSigner},
    database::{GunDatabase, ProtocolKind, StringDescriptor},
    keychain::ProtocolSecret,
};
use anyhow::{anyhow, Context};
use bdk::{
    bitcoin::{
        secp256k1::Secp256k1,
        util::bip32::{ExtendedPrivKey, ExtendedPubKey, Fingerprint},
        Network,
    },
    database::MemoryDatabase,
    descriptor::{ExtendedDescriptor, IntoWalletDescriptor},
    keys::{
        bip39::{Language, Mnemonic, WordCount},
        GeneratableKey, GeneratedKey,
    },
    miniscript::Segwitv0,
    sled,
    template::{Bip84, Bip84Public},
    KeychainKind, Wallet,
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
        /// Password protect your coins
        #[structopt(long)]
        use_passphrase: bool,
    },
    /// Initialize using a output descriptor
    ///
    /// This option is intended for people who know what they are doing!
    Descriptor {
        #[structopt(flatten)]
        common_args: CommonArgs,
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
    xfp: Fingerprint,
    bip84: BIP84Export,
}

#[derive(Deserialize)]
struct BIP84Export {
    xpub: ExtendedPubKey,
}

pub fn run_init(wallet_dir: &std::path::Path, cmd: InitOpt) -> anyhow::Result<CmdOutput> {
    if wallet_dir.exists() {
        return Err(anyhow!(
            "wallet directory {} already exists -- delete it to create a new wallet",
            wallet_dir.display()
        ));
    }
    let secp = Secp256k1::<bdk::bitcoin::secp256k1::All>::new();

    let (config, protocol_secret, (external, internal), seed_words_file) = match cmd {
        InitOpt::Seed {
            common_args,
            from_existing,
            n_words,
            use_passphrase,
        } => {
            let mnemonic = match from_existing {
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
                    Mnemonic::parse(&seed_words).context("parsing existing seedwords")?
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
                    .expect("cannot fail");
                    seed_words.into_key()
                }
            };

            let passphrase = if use_passphrase {
                eprintln!("WARNING: If you lose or forget your passphrase, you will lose access to your funds.");
                eprintln!("WARNING: You MUST store your passphrase with your seed words in order to make a complete backup.");
                loop {
                    let passphrase =
                        rpassword::prompt_password_stderr("Enter your wallet passphrase:")?;
                    let passphrase_confirmation =
                        rpassword::prompt_password_stderr("Enter your wallet passphrase again:")?;
                    if !passphrase.eq(&passphrase_confirmation) {
                        eprintln!("Mismatching passphrases. Try again.\n")
                    } else {
                        break passphrase;
                    }
                }
            } else {
                "".to_string()
            };

            let sw_file = wallet_dir.join("seed.txt");
            if cmd::read_yn("Do you want gun to print out your seed words now to make a backup?") {
                let printed = mnemonic
                    .word_iter()
                    .enumerate()
                    .map(|(i, word)| format!("{}: {}", i + 1, word))
                    .collect::<Vec<_>>()
                    .join("\n");
                println!("{printed}");
            } else {
                eprintln!(
                    "Err okay then...make sure you backup {} after this.",
                    sw_file.display()
                );
            }

            let seed_bytes = mnemonic.to_seed(passphrase);
            let xpriv = ExtendedPrivKey::new_master(common_args.network, &seed_bytes).unwrap();

            let bip85_bytes: [u8; 64] = get_bip85_bytes(xpriv, 330, &secp);

            let master_fingerprint = xpriv.fingerprint(&secp);

            let signers = vec![GunSigner::SeedWordsFile {
                file_path: sw_file.clone(),
                passphrase_fingerprint: if use_passphrase {
                    Some(master_fingerprint)
                } else {
                    None
                },
            }];

            let (external, _) = Bip84(xpriv, KeychainKind::External)
                .into_wallet_descriptor(&secp, common_args.network)?;
            let (internal, _) = Bip84(xpriv, KeychainKind::Internal)
                .into_wallet_descriptor(&secp, common_args.network)?;
            (
                Config {
                    signers,
                    ..Config::default_config(common_args.network)
                },
                Some(bip85_bytes),
                (external.to_string(), Some(internal.to_string())),
                Some((sw_file, mnemonic.word_iter().collect::<Vec<_>>().join(" "))),
            )
        }
        InitOpt::Descriptor {
            common_args,
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

            (
                Config::default_config(common_args.network),
                None,
                (external, internal),
                None,
            )
        }
        InitOpt::XPub {
            common_args,
            ref xpub,
        } => {
            let external = set_network(&format!("wpkh({}/0/*)", xpub), common_args.network)?;
            let internal = set_network(&format!("wpkh({}/1/*)", xpub), common_args.network)?;

            (
                Config::default_config(common_args.network),
                None,
                (external, Some(internal)),
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

            let (external, _) = Bip84Public(
                wallet_export.bip84.xpub,
                wallet_export.xfp,
                KeychainKind::External,
            )
            .into_wallet_descriptor(&secp, common_args.network)?;
            let (internal, _) = Bip84Public(
                wallet_export.bip84.xpub,
                wallet_export.xfp,
                KeychainKind::Internal,
            )
            .into_wallet_descriptor(&secp, common_args.network)?;

            let signers = vec![GunSigner::PsbtDir {
                path: coldcard_sd_dir,
            }];

            (
                Config {
                    signers,
                    ..Config::default_config(common_args.network)
                },
                bip85_bytes,
                (external.to_string(), Some(internal.to_string())),
                None,
            )
        }
    };

    std::fs::create_dir(&wallet_dir)?;

    let config_file = wallet_dir.join("config.json");

    let gun_db = GunDatabase::new(
        sled::open(wallet_dir.join("database.sled").to_str().unwrap())?.open_tree("gun")?,
    );

    if let Some(protocol_secret) = protocol_secret {
        gun_db.insert_entity(ProtocolKind::Bet, ProtocolSecret::Bytes(protocol_secret))?;
    }

    let _ = ExtendedDescriptor::parse_descriptor(&secp, &external)
        .context("validating external descriptor")?;
    gun_db.insert_entity(KeychainKind::External, StringDescriptor(external))?;

    if let Some(internal) = internal {
        let _ = ExtendedDescriptor::parse_descriptor(&secp, &internal)
            .context("validating internal descriptor")?;
        gun_db.insert_entity(KeychainKind::Internal, StringDescriptor(internal))?;
    }

    cmd::write_config(&config_file, config)?;

    if let Some((path, content)) = seed_words_file {
        std::fs::write(path, content)?;
    }

    eprintln!("gun initialized successfully to {}", wallet_dir.display());
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
