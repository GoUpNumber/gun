#![feature(backtrace)]
use anyhow::{anyhow, Context};
use bdk::{Wallet, bitcoin::Network, bitcoin::Address, blockchain::{AnyBlockchain, Blockchain, ConfigurableBlockchain, Progress}, database::BatchDatabase, reqwest, sled};
use bdk_cli::structopt::StructOpt;
use bweet::{
    amount_ext::FromCliStr,
    bet_database::{BetDatabase, BetState},
    bitcoin::Amount,
    cmd,
    config::Config,
    keychain::Keychain,
    party::{Party, Proposal},
};
use clap::{Arg, SubCommand};
use std::{fs, path::PathBuf, str::FromStr};

macro_rules! cli_app {
    ($app:ident) => {
        let default_dir = match std::env::var("BWEET_DIR") {
            Ok(bweet_dir) => PathBuf::from(bweet_dir),
            Err(_) => {
                let mut default_dir = PathBuf::new();
                default_dir.push(&dirs::home_dir().unwrap());
                default_dir.push(".bweet");
                default_dir
            }
        };
        let $app = bdk_cli::WalletSubCommand::clap()
            .subcommand(
                SubCommand::with_name("bet")
                    .about("Make or take a bet")
                    .subcommand(
                        SubCommand::with_name("propose")
                            .about("Propose a bet")
                            .arg(
                                Arg::with_name("value")
                                    .required(true)
                                    .help("The value of the bet"),
                            )
                            .arg(
                                Arg::with_name("event-url")
                                    .required(true)
                                    .help("The url where the oracle is publishing the event"),
                            ),
                    )
                    .subcommand(SubCommand::with_name("list").about("List outstanding bets"))
                    .subcommand(
                        SubCommand::with_name("offer")
                            .about("Make an offer in response to a proposal")
                            .arg(
                                Arg::with_name("value")
                                    .required(true)
                                    .help("The value of the bet"),
                            )
                            .arg(Arg::with_name("proposal").required(true).help(""))
                            .arg(Arg::with_name("choose").required(true).short("c").takes_value(true).help("which outcome to choose"))
                    )
                    .subcommand(
                        SubCommand::with_name("take")
                            .about("Take an offer to one of your proposals")
                            .arg(
                                Arg::with_name("id")
                                    .help("The id of the proposal this offer was made for")
                                    .required(true),
                            )
                            .arg(
                                Arg::with_name("offer")
                                    .help("The offer you want to take")
                                    .required(true),
                            ),
                    )
                    .subcommand(
                        SubCommand::with_name("claim")
                            .about("Claim the winnings from your bets")
                            .arg(Arg::with_name("to").takes_value(true).help("Claim to particular address"))
                            .arg(Arg::with_name("value").takes_value(true).help("How much to claim (default is claims all)"))
                    )
                    .subcommand(
                        SubCommand::with_name("show")
                            .about("View a proposal or offer")
                            .arg(
                                Arg::with_name("message")
                                    .required(true)
                                    .help("The proposal or offer string"),
                            ),
                    )
                    .subcommand(
                        SubCommand::with_name("oracle")
                            .alias("oracles")
                            .about("Modify/view list of trusted oracles")
                            .subcommand(SubCommand::with_name("list").about("list trusted oracles"))
                            .subcommand(SubCommand::with_name("add").about("Trust an oracle")),
                    ),
            )
            .subcommand(
                SubCommand::with_name("init")
                    .about("Initialize the wallet")
                    .arg(
                        Arg::with_name("network")
                            .required(true)
                            .help("The network name (bitcoin|regtest|testnet)"),
                    ),
            )
            .subcommand(
                SubCommand::with_name("dev")
                    .about("Development utilities")
                    .subcommand(
                        SubCommand::with_name("nigiri")
                            .about("Interact with nigiri")
                            .subcommand(SubCommand::with_name("start").about("runs nigiri start"))
                            .subcommand(SubCommand::with_name("stop").about("runs nigiri stop"))
                            .subcommand(
                                SubCommand::with_name("reset").about("runs nigiri stop --delete"),
                            )
                            .subcommand(
                                SubCommand::with_name("fund")
                                    .about("funds the wallet using the nigiri faucet"),
                            ),
                    )
                    .subcommand(
                        SubCommand::with_name("reset")
                            .about("Deletes the wallet's database (keeping the seedwords)"),
                    ),
            )
            .subcommand(
                SubCommand::with_name("config")
                    .about("Configuration utilities")
                    .subcommand(SubCommand::with_name("show")),
            )
            .arg(
                Arg::with_name("bweet-dir")
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
    let wallet_dir = PathBuf::from(&matches.value_of_os("bweet-dir").unwrap());

    match matches.subcommand() {
        ("init", Some(args)) => {
            let sw_file = get_seed_words_file(&wallet_dir);
            if sw_file.exists() {
                return Err(anyhow!(
                    "A seed words file already exists at {}.",
                    sw_file.as_path().display()
                ));
            }
            cmd::init(
                wallet_dir,
                Network::from_str(args.value_of("network").unwrap())?,
            )?;
            let seed_words = fs::read_to_string(sw_file.clone())
                .context("unable to read seed words after writing them")?;
            println!("Writing seed words to {}", sw_file.as_path().display());
            println!("===== BIP39 seed words =====");
            println!("{}", seed_words);
        }
        ("config", Some(matches)) => match matches.subcommand() {
            ("show", _) => {
                let config = cmd::get_config(&wallet_dir)?;
                println!("{}", serde_json::to_string_pretty(&config).unwrap());
            }
            _ => println!("{}", matches.usage()),
        },
        ("bet", Some(matches)) => match matches.subcommand() {
            ("oracles", Some(matches)) => match matches.subcommand() {
                ("list", _) => {
                    let bet_db = get_bet_db(&wallet_dir)?;
                    let table = cmd::bet::list_oracles(&bet_db);
                    println!("{}", table.render());
                }
                _ => println!("{}", matches.usage()),
            },
            ("propose", Some(args)) => {
                let party = load_party(&wallet_dir).await?;
                let value = match args.value_of("value") {
                    Some("all") => Amount::from_sat(party.wallet().get_balance()?),
                    Some(value) => Amount::from_cli_str(value)?,
                    None => {
                        return Err(anyhow!(
                            "requires a value of BTC with denomination e.g. 0.01BTC"
                        ));
                    }
                };
                let event_url = reqwest::Url::parse(args.value_of("event-url").unwrap())?;
                let proposal = cmd::bet::propose(party, event_url, value).await?;
                println!("{}", proposal.to_string());
            }
            ("list", _) => {
                {
                    let (wallet, bet_db, keychain, config) = load_wallet(&wallet_dir).await?;
                    let party = Party::new(wallet, bet_db, keychain, config.blockchain);
                    poke_bets(&party).await;
                }
                let bet_db = get_bet_db(&wallet_dir)?;
                let table = cmd::bet::list_bets(&bet_db);
                println!("{}", table.render());
            }
            ("offer", Some(args)) => {
                let (wallet, bet_db, keychain, config) = load_wallet(&wallet_dir).await?;
                let party = Party::new(wallet, bet_db, keychain, config.blockchain);
                let proposal = Proposal::from_str(args.value_of("proposal").unwrap())
                    .map_err(|e| anyhow!("inlvaid proposal: {}", e))?;
                let value = match args.value_of("value") {
                    Some("all") => Amount::from_sat(party.wallet().get_balance()?),
                    Some(value) => Amount::from_cli_str(value)?,
                    None => {
                        return Err(anyhow!(
                            "requires a value of BTC with denomination e.g. 0.01BTC"
                        ));
                    }
                };
                let choice = args.value_of("choose").unwrap();
                let (bet, offer, cipher) = cmd::bet::generate_offer(&party, proposal, value, choice).await?;
                println!("{}", bet.prompt());
                if read_answer() {
                    let (_bet_id, encrypted_offer) = party.save_and_encrypt_offer(bet, offer, cipher)?;
                    println!("{}", encrypted_offer.to_string());
                }
            }
            ("take", Some(args)) => {
                let (wallet, bet_db, keychain, config) = load_wallet(&wallet_dir).await?;
                let party = Party::new(wallet, bet_db, keychain, config.blockchain);
                let bet_id =
                    u32::from_str(args.value_of("id").unwrap()).context("Invalid bet id")?;
                let encrypted_offer =
                    bweet::party::EncryptedOffer::from_str(args.value_of("offer").unwrap())
                        .context("Decoding encrypted offer")?;

                let validated_offer =
                    party.decrypt_and_validate_offer(bet_id, encrypted_offer).await?;

                println!("{}", validated_offer.bet.prompt());

                if read_answer() {
                    let tx = party.take_offer(validated_offer)?;
                    println!(
                        "The funding transaction txid is {}. Attempting to broadcast...",
                        tx.txid()
                    );
                }
                party.take_next_action(bet_id).await?;
            }
            ("decode", Some(args)) => {
                let message = args.value_of("message").unwrap();
                if let Ok(proposal) = Proposal::from_str(message) {
                    println!("{}", serde_json::to_string_pretty(&proposal).unwrap());
                }
                // Todo offer
            }
            ("claim", Some(args)) => {
                let party =  load_party(&wallet_dir).await?;
                let to =  args.value_of("to").map(|addr|Address::from_str(addr).map(|a| a.script_pubkey())).transpose()?;
                let value = args.value_of("value").map(|value| Amount::from_str(value)).transpose()?;
                match party.claim_to(to,value)? {
                    Some(claim) => {
                        println!("broadcasting claim tx: {}", claim.tx.txid());
                        party.wallet().broadcast(claim.tx).await?;
                    },
                    None => return Err(anyhow!("There are no coins to claim")),
                }
            }
            _ => {
                println!("{}", matches.usage());
            }
        },
        ("dev", Some(matches)) => match matches.subcommand() {
            ("nigiri", Some(matches)) => match matches.subcommand() {
                ("start", _) => {
                    bweet::cmd::dev::nigiri_start()?;
                }
                ("stop", _) => {
                    bweet::cmd::dev::nigiri_stop()?;
                }
                ("reset", _) => {
                    bweet::cmd::dev::reset(&wallet_dir)?;
                    bweet::cmd::dev::nigiri_stop()?;
                    bweet::cmd::dev::nigiri_start()?;
                }
                ("fund", _) => {
                    let (wallet, _, _, _) = load_wallet(&wallet_dir).await?;
                    if wallet.network() != Network::Regtest {
                        return Err(anyhow!("dev fund only works on regtest"));
                    }
                    let old_balance = wallet.get_balance()?;
                    bweet::cmd::dev::nigiri_fund(&wallet).await?;
                    while {
                        let new_balance = wallet.get_balance()?;
                        new_balance == old_balance
                    } {
                        wallet.sync(SyncProgress, None).await?;
                    }
                    let new_balance = wallet.get_balance()?;
                    println!("old balance: {}\nnew balance: {}", old_balance, new_balance)
                }
                _ => {
                    println!("{}", matches.usage());
                }
            },
            ("reset", _) => {
                bweet::cmd::dev::reset(&wallet_dir)?;
            }
            _ => {
                println!("{}", matches.usage());
            }
        },
        _ => {
            let (wallet, _, _, _) = load_wallet(&wallet_dir).await?;
            let wallet_command = bdk_cli::WalletSubCommand::from_clap(&matches);
            let result = match wallet_command {
                bdk_cli::WalletSubCommand::OnlineWalletSubCommand(online_command) => {
                    bdk_cli::handle_online_wallet_subcommand(&wallet, online_command).await?
                }
                bdk_cli::WalletSubCommand::OfflineWalletSubCommand(offline_command) => {
                    bdk_cli::handle_offline_wallet_subcommand(&wallet, offline_command)?
                }
            };

            println!("{}", serde_json::to_string(&result).unwrap());
        }
    };
    Ok(())
}

fn read_answer() -> bool {
    use std::io::{self, BufRead};
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();
    println!("[y/n]?");
    lines
        .find_map(
            |line| match line.unwrap().trim_end().to_lowercase().as_str() {
                "y" => Some(true),
                "n" => Some(false),
                _ => {
                    println!("[y/n]?");
                    None
                }
            },
        )
        .unwrap_or(false)
}

fn get_seed_words_file(wallet_dir: &PathBuf) -> PathBuf {
    let mut seed_words_file = wallet_dir.clone();
    seed_words_file.push("seed.txt");
    seed_words_file
}

fn get_bet_db(wallet_dir: &PathBuf) -> anyhow::Result<BetDatabase> {
    let mut db_file = wallet_dir.clone();
    db_file.push("database.sled");
    let database = sled::open(db_file.to_str().unwrap())?;
    let bet_db = BetDatabase::new(database.open_tree("bets")?);
    Ok(bet_db)
}

async fn load_party(wallet_dir: &PathBuf) -> anyhow::Result<Party<impl Blockchain, impl BatchDatabase>> {
    let (wallet, bet_db, keychain, config) = load_wallet(&wallet_dir).await?;
    let party = Party::new(wallet, bet_db, keychain, config.blockchain);
    Ok(party)
}

async fn load_wallet(
    wallet_dir: &PathBuf,
) -> anyhow::Result<(
    Wallet<impl Blockchain, impl BatchDatabase>,
    BetDatabase,
    Keychain,
    Config,
)> {
    use bip39::{Language, Mnemonic, Seed};

    if !wallet_dir.exists() {
        return Err(anyhow!(
            "No wallet found at {}. Run `bweet init` to set a new one up or set --bweet-dir.",
            wallet_dir.as_path().display()
        ));
    }

    let config = cmd::get_config(&wallet_dir)?;
    let keychain = {
        let sw_file = get_seed_words_file(&wallet_dir);
        let seed_words = fs::read_to_string(sw_file.clone())?;
        let mnemonic = Mnemonic::from_phrase(&seed_words, Language::English).map_err(|e| {
            anyhow!(
                "parsing seed phrase in '{}' failed: {}",
                sw_file.as_path().display(),
                e
            )
        })?;
        let mut seed_bytes = [0u8; 64];
        let seed = Seed::new(&mnemonic, "");
        seed_bytes.copy_from_slice(seed.as_bytes());
        Keychain::new(seed_bytes)
    };

    let database = {
        let mut db_file = wallet_dir.clone();
        db_file.push("database.sled");
        sled::open(db_file.to_str().unwrap())?
    };

    let wallet = {
        let wallet_db = database.open_tree("wallet")?;
        let descriptor = bdk::template::Bip84(
            keychain.main_wallet_xprv(config.network),
            bdk::KeychainKind::External,
        );
        Wallet::new(
            descriptor,
            None,
            config.network,
            wallet_db,
            AnyBlockchain::from_config(&config.blockchain)?,
        )
        .await
        .context("Initializing wallet failed")?
    };

    let bet_db = BetDatabase::new(database.open_tree("bets")?);

    Ok((wallet, bet_db, keychain, config))
}

async fn poke_bets<B: Blockchain, D: BatchDatabase>(
    party: &Party<B, D>,
) {
    for (bet_id, _) in party.bet_db().list_entities_print_error::<BetState>() {
        match party.take_next_action(bet_id).await {
            Ok(_updated) => {}
            Err(e) => eprintln!("Error trying to take action on bet {}: {:?}", bet_id, e),
        }
    }
}

struct SyncProgress;

impl Progress for SyncProgress {
    fn update(&self, progress: f32, message: Option<String>) -> Result<(), bdk::Error> {
        println!("progress {}, {:?}", progress, message);
        Ok(())
    }
}
