#![feature(backtrace)]
use anyhow::{anyhow, Context};
use bdk::{
    bitcoin::Network, blockchain::EsploraBlockchain, descriptor::Segwitv0, keys::GeneratedKey,
    reqwest, sled, Wallet,
};
use bdk_cli::structopt::StructOpt;
use bweet::{
    bitcoin::Amount,
    keychain::Keychain,
    party::{Party, Proposal},
};
use clap::{Arg, SubCommand};
use std::{path::PathBuf, str::FromStr};

macro_rules! cli_app {
    ($app:ident) => {
        let mut default_dir = PathBuf::new();
        default_dir.push(&dirs::home_dir().unwrap());
        default_dir.push(".bweet");

        let $app = bdk_cli::WalletSubCommand::clap()
            .subcommand(
                SubCommand::with_name("bet")
                    .about("Make or take a bet")
                    .subcommand(
                        SubCommand::with_name("propose")
                            .about("Propose a bet")
                            .arg(Arg::with_name("event-url").required(true).help("The url where the oracle is publishing the event"))
                            .arg(Arg::with_name("value").required(true).help("The value of the bet"))
                    )
                    .subcommand(
                        SubCommand::with_name("offer")
                            .about("Make an offer in response to a proposal")
                            .arg(Arg::with_name("proposal").required(true)),
                    ),
            )
            .subcommand(
                SubCommand::with_name("test")
                    .about("Test utilities")
                    .subcommand(SubCommand::with_name("fund_wallet")),
            )
            .arg(
                Arg::with_name("wallet-dir")
                    .short("d")
                    .value_name("DIRECTORY")
                    .default_value_os(default_dir.as_os_str()),
            );
    };
}


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    cli_app!(app);
    let matches = app.get_matches();
    let wallet_dir = PathBuf::from(&matches.value_of_os("wallet-dir").unwrap());
    let (db_file, seed) = prepare_db(wallet_dir)?;
    let database = sled::open(db_file.to_str().unwrap())?;
    let wallet_db = database.open_tree("wallet")?;
    let bets_db = database.open_tree("bets")?;
    let esplora_url = "http://localhost:3000".to_string();
    let esplora = EsploraBlockchain::new(&esplora_url, None);
    let keychain = Keychain::new(seed);
    let descriptor = bdk::template::BIP84(
        keychain.main_wallet_xprv(Network::Regtest),
        bdk::KeychainKind::External,
    );

    let wallet = Wallet::new(descriptor, None, Network::Regtest, wallet_db, esplora)
        .await
        .context("Initializing wallet failed")?;

    let party = Party::new(wallet, bets_db, keychain, esplora_url);

    let result = match matches.subcommand() {
        ("bet", Some(matches)) => {
            match matches.subcommand() {
                ("propose", Some(args)) => {
                    let event_url = reqwest::Url::parse(args.value_of("event-url").unwrap())?;
                    let value = match args.value_of("value") {
                        Some("all") => Amount::from_sat(party.wallet().get_balance()?),
                        Some(value) => Amount::from_str(value)?,
                        _ => {
                            return Err(anyhow!("{}", args.usage()))
                        }
                    };
                    let (_bet_id, proposal) = party.make_proposal_from_url(event_url, value)
                        .await?;

                    proposal.to_string()
                }
                ("offer", Some(args)) => {
                    let proposal = Proposal::from_str(args.value_of("proposal").unwrap())
                        .map_err(|e| anyhow!("inlvaid proposal: {}", e))?;
                    let (_bet_id, offer) = party
                        .make_offer(
                            proposal,
                            true,
                            Amount::from_str_with_denomination("0.02 BTC").unwrap(),
                        )
                        .await
                        .context("failed to generate offer")?;
                    offer.to_string()
                }
                _ => matches.usage().into(),
            }
        }
        ("test", _) => {
            let wallet = party.wallet();
            let old_balance = wallet.get_balance()?;
            bweet::cmd::fund_wallet(&wallet).await?;
            while {
                let new_balance = wallet.get_balance()?;
                new_balance == old_balance
            } {
                wallet.sync(bdk::blockchain::log_progress(), None).await?;
            }

            let new_balance = wallet.get_balance()?;
            format!("old balance: {}\nnew balance: {}", old_balance, new_balance)
        }
        _ => {
            let wallet_command = bdk_cli::WalletSubCommand::from_clap(&matches);
            let result = match wallet_command {
                bdk_cli::WalletSubCommand::OnlineWalletSubCommand(online_command) => {
                    bdk_cli::handle_online_wallet_subcommand(party.wallet(), online_command).await?
                }
                bdk_cli::WalletSubCommand::OfflineWalletSubCommand(offline_command) => {
                    bdk_cli::handle_offline_wallet_subcommand(party.wallet(), offline_command)?
                }
            };
            serde_json::to_string(&result).unwrap()
        }
    };
    println!("{}", result);
    Ok(())
}

fn prepare_db(wallet_dir: PathBuf) -> anyhow::Result<(PathBuf, [u8; 64])> {
    use bdk::keys::GeneratableKey;
    use bip39::{Language, Mnemonic, MnemonicType, Seed};
    use std::fs;

    let mut seed_words_file = wallet_dir.clone();
    seed_words_file.push("seed.txt");

    if !wallet_dir.exists() {
        println!("Creating database in {}", wallet_dir.as_path().display());
        std::fs::create_dir(&wallet_dir)?;

        let seed_words: GeneratedKey<_, Segwitv0> =
            Mnemonic::generate((MnemonicType::Words12, Language::English))
                .map_err(|_| anyhow!("generating seed phrase failed"))?;
        let seed_words = &*seed_words;

        println!(
            "Creating seed words in {}",
            seed_words_file.as_path().display()
        );
        println!("==== BIP39 SEED WORDS ====\n{}", seed_words.phrase());
        fs::write(seed_words_file.clone(), seed_words.phrase())?;
    }

    let mut db_dir = wallet_dir.clone();
    db_dir.push("database.sled");

    let seed_words = fs::read_to_string(seed_words_file.clone())?;
    let mnemonic = Mnemonic::from_phrase(&seed_words, Language::English).map_err(|_| {
        anyhow!(
            "parsing seed phrase in '{}' failed",
            seed_words_file.as_path().display()
        )
    })?;
    let mut seed_bytes = [0u8; 64];
    let seed = Seed::new(&mnemonic, "");
    seed_bytes.copy_from_slice(seed.as_bytes());
    Ok((wallet_dir, seed_bytes))
}
