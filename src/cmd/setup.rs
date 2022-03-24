use crate::{
    bip85::get_bip85_bytes,
    cmd::{self},
    config::{Config, GunSigner},
    database::{GunDatabase, ProtocolKind, RemoteNonces, StringDescriptor},
    elog,
    frost::KeyGenOutput,
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
    template::{Bip84, Bip84Public, Bip86},
    KeychainKind, Wallet,
};
use miniscript::{Descriptor, DescriptorPublicKey, TranslatePk1};
use olivia_secp256k1::fun::hex;
use serde::Deserialize;
use std::{
    fs::{self},
    io,
    path::PathBuf,
    str::FromStr,
};
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
    pub network: Network,
}

#[derive(Clone, Copy, Debug, serde::Deserialize, serde::Serialize)]
pub enum AddressKind {
    Wpkh,
    Tr,
}

impl FromStr for AddressKind {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "wpkh" => AddressKind::Wpkh,
            "tr" => AddressKind::Tr,
            _ => return Err(anyhow!("invalid address kind. Must be p2wpkh or p2tr")),
        })
    }
}

impl std::fmt::Display for AddressKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddressKind::Wpkh => write!(f, "wpkh"),
            AddressKind::Tr => write!(f, "tr"),
        }
    }
}

#[derive(Clone, Debug, StructOpt)]
pub enum SetupOpt {
    /// Setup using a seedphrase
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
        #[structopt(long, default_value = "tr", name = "wpkh|tr")]
        address_kind: AddressKind,
    },
    /// Setup using a output descriptors
    ///
    /// This option is intended for people who know what they are doing!
    /// Keep in mind that descriptors with private keys in them will be stored in the database as plaintext.
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
    /// Setup using an extended public key descriptor.
    ///
    /// The descriptor must be in [masterfingerprint/hardened'/derivation'/path']xkey format e.g.
    ///
    /// $ gun setup xkey "[E83E2DB9/84'/0'/0']xpub66...mSXJj"
    ///
    /// The key can be an xpriv or or an xpub.
    /// If you use an xpriv, keep in mind that gun will store the descriptor in the database in plaintext.
    #[structopt(name = "xkey")]
    XKey {
        #[structopt(flatten)]
        common_args: CommonArgs,
        /// the extended key descriptor
        #[structopt(name = "xkey-descriptor")]
        xkey: String,
        #[structopt(long, default_value = "tr", name = "wpkh|tr")]
        address_kind: AddressKind,
    },
    /// Setup with a ColdCard via SD card
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
    /// Initialize a Schnorr threshold multisig wallet
    Frost(FrostSetup),
}

#[derive(Deserialize)]
struct WalletExport {
    xfp: Fingerprint,
    bip84: BIP84Export,
}

#[derive(Clone, Debug, StructOpt)]
pub enum FrostSetup {
    Start {
        /// The working directory where we will collect the other participants data
        #[structopt(parse(from_os_str))]
        working_dir: PathBuf,
        /// Number of signers needed to complete a signature
        threshold: usize,
        #[structopt(flatten)]
        common_args: CommonArgs,
    },
    Add {
        /// The working directory where we will collect the other participants data
        working_dir: PathBuf,
    },
}

#[derive(Deserialize)]
struct BIP84Export {
    xpub: ExtendedPubKey,
}

pub fn run_setup(wallet_dir: &std::path::Path, cmd: SetupOpt) -> anyhow::Result<CmdOutput> {
    if wallet_dir.exists() {
        return Err(anyhow!(
            "wallet directory {} already exists -- delete it to create a new wallet",
            wallet_dir.display()
        ));
    }
    let secp = Secp256k1::<bdk::bitcoin::secp256k1::All>::new();

    std::fs::create_dir(&wallet_dir)?;

    let config_file = wallet_dir.join("config.json");

    let gun_db = GunDatabase::new(
        sled::open(wallet_dir.join("database.sled").to_str().unwrap())?.open_tree("gun")?,
    );

    let (config, protocol_secret, (external, internal), seed_words_file) = match cmd {
        SetupOpt::Seed {
            common_args,
            from_existing,
            n_words,
            use_passphrase,
            address_kind,
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
                elog!(@warning "If you lose or forget your passphrase, you will lose access to your funds.");
                elog!(@warning "You MUST store your passphrase with your seed words in order to make a complete backup.");
                loop {
                    let passphrase =
                        rpassword::prompt_password_stderr("Enter your wallet passphrase:")?;
                    let passphrase_confirmation =
                        rpassword::prompt_password_stderr("Enter your wallet passphrase again:")?;
                    if !passphrase.eq(&passphrase_confirmation) {
                        elog!(@user_error "Mismatching passphrases. Try again.\n");
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
                println!("{}", printed);
            } else {
                elog!(
                    @suggestion
                    "Err okay then...make sure you backup {} after this.",
                    sw_file.display()
                );
            }

            let seed_bytes = mnemonic.to_seed(passphrase);
            let xpriv = ExtendedPrivKey::new_master(common_args.network, &seed_bytes).unwrap();

            let bip85_bytes: [u8; 64] = get_bip85_bytes(xpriv, 330, &secp);

            let master_fingerprint = xpriv.fingerprint(&secp);

            let signers = vec![GunSigner::SeedWordsFile {
                passphrase_fingerprint: if use_passphrase {
                    Some(master_fingerprint)
                } else {
                    None
                },
            }];

            let (external, internal) = match address_kind {
                AddressKind::Tr => {
                    let (external, _) = Bip86(xpriv, KeychainKind::External)
                        .into_wallet_descriptor(&secp, common_args.network)?;
                    let (internal, _) = Bip86(xpriv, KeychainKind::Internal)
                        .into_wallet_descriptor(&secp, common_args.network)?;
                    (external, internal)
                }
                AddressKind::Wpkh => {
                    let (external, _) = Bip84(xpriv, KeychainKind::External)
                        .into_wallet_descriptor(&secp, common_args.network)?;
                    let (internal, _) = Bip84(xpriv, KeychainKind::Internal)
                        .into_wallet_descriptor(&secp, common_args.network)?;
                    (external, internal)
                }
            };
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
        SetupOpt::Descriptor {
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
        SetupOpt::XKey {
            common_args,
            ref xkey,
            address_kind,
        } => {
            let external = set_network(
                &format!("{}({}/0/*)", address_kind, xkey),
                common_args.network,
            )?;
            let internal = set_network(
                &format!("{}({}/1/*)", address_kind, xkey),
                common_args.network,
            )?;
            (
                Config::default_config(common_args.network),
                None,
                (external, Some(internal)),
                None,
            )
        }
        SetupOpt::Coldcard {
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
            let mut wallet_export = serde_json::from_str::<WalletExport>(&wallet_export_str)?;
            wallet_export.bip84.xpub.network = common_args.network;
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
        SetupOpt::Frost(frost_setup) => {
            use crate::frost;
            let (FrostSetup::Start { working_dir, .. } | FrostSetup::Add { working_dir }) =
                &frost_setup;
            let working_dir = working_dir.clone();
            let setup_file = working_dir.join("frost-setup.json");
            let KeyGenOutput {
                secret_share,
                joint_key,
                my_poly_secret,
                nonces,
                my_signer_index,
                network,
            } = frost::run_frost_setup(&setup_file, frost_setup)?;

            let secret_share_file = wallet_dir.join("share.hex");
            std::fs::write(
                secret_share_file,
                secret_share.to_string() + &my_poly_secret.to_string(),
            )?;

            for (i, nonce_list) in nonces.into_iter().enumerate() {
                let remote_nonces = RemoteNonces {
                    nonce_list,
                    index: 0,
                };

                gun_db.insert_entity(i, remote_nonces)?;
            }

            let external = format!("tr({})", joint_key.public_key());
            (
                Config {
                    signers: vec![GunSigner::Frost {
                        joint_key,
                        my_signer_index,
                        working_dir,
                    }],
                    ..Config::default_config(network)
                },
                None,
                (external, None),
                None,
            )
        }
    };

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

    elog!(@celebration "Successfully created wallet at {}", wallet_dir.display());
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
