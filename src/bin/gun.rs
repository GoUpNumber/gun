use anyhow::anyhow;
use bdk::blockchain::esplora::EsploraBlockchainConfig;
use gun_wallet::cmd::{
    self, bet::BetOpt, AddressOpt, InitOpt, SendOpt, SplitOpt, TransactionOpt, UtxoOpt,
};
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt, Debug, Clone)]
/// A CLI Bitcoin wallet for plebs, degenerates and revolutionaries.
pub struct Opt {
    #[structopt(parse(from_os_str), short("d"), env = "GUN_DIR")]
    /// The wallet data directory.
    gun_dir: Option<PathBuf>,
    #[structopt(subcommand)]
    command: Commands,
    #[structopt(short, long)]
    /// Tell the wallet to sync itself.
    sync: bool,
    #[structopt(short, long)]
    /// Return output in JSON format
    json: bool,
    /// Return outupt in simplified UNIX table (tabs and newlines)
    #[structopt(short, long)]
    tabs: bool,
}

#[derive(StructOpt, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum Commands {
    /// Make or take a bet
    Bet(BetOpt),
    /// View the balance of the wallet
    Balance,
    /// Get addresses
    Address(AddressOpt),
    /// View Transactions
    Tx(TransactionOpt),
    /// View Utxos
    Utxo(UtxoOpt),
    /// Send funds out of wallet
    Send(SendOpt),
    /// Initialize a wallet
    Init(InitOpt),
    /// Split coins into evenly sized outputs.
    Split(SplitOpt),
}

fn main() -> anyhow::Result<()> {
    let opt = Opt::from_args();
    let sync = opt.sync;

    let wallet_dir = opt
        .gun_dir
        .unwrap_or_else(|| dirs::home_dir().unwrap().join(".gun"));

    let res = if let Commands::Init(opt) = opt.command {
        cmd::run_init(&wallet_dir, opt)
    } else {
        let (wallet, keychain, config) = cmd::load_wallet(&wallet_dir)?;

        if sync {
            use Commands::*;

            if let Balance | Address(_) | Send(_) | Tx(_) | Utxo(_) = opt.command {
                let EsploraBlockchainConfig {
                    stop_gap,
                    base_url,
                    concurrency,
                    ..
                } = config.blockchain_config();
                eprintln!(
                    "syncing wallet with {} (stop_gap: {}, parallel_connections: {})",
                    base_url,
                    stop_gap,
                    concurrency.unwrap_or(1)
                );
                wallet.sync()?;
            }

            // we poke bets to update balance from bets as well.
            if let Balance = opt.command {
                wallet.poke_bets()
            }
        }

        match opt.command {
            Commands::Bet(opt) => {
                let keychain = match keychain {
                    Some(keychain) => keychain,
                    None => {
                        return Err(anyhow!(
                        "This wallet wasn't set up with a protocol secret so you can't do betting"
                    ))
                    }
                };
                cmd::run_bet_cmd(&wallet, &keychain, opt, sync)
            }
            Commands::Balance => cmd::run_balance(&wallet, sync),
            Commands::Address(opt) => cmd::get_address(&wallet, opt),
            Commands::Send(opt) => cmd::run_send(&wallet, opt),
            Commands::Init(_) => unreachable!("we handled init already"),
            Commands::Tx(opt) => cmd::run_transaction_cmd(&wallet, opt),
            Commands::Utxo(opt) => cmd::run_utxo_cmd(&wallet, opt),
            Commands::Split(opt) => cmd::run_split_cmd(&wallet, opt),
        }
    };

    match res {
        Ok(output) => {
            if opt.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&output.render_json()).unwrap()
                )
            } else if opt.tabs {
                println!("{}", output.render_simple())
            } else if let Some(output) = output.render() {
                println!("{}", output)
            }
        }
        Err(e) => {
            if opt.json {
                let err_json = serde_json::json!({
                    "error" : format!("{}", e),
                });
                println!("{}", serde_json::to_string_pretty(&err_json).unwrap());
                std::process::exit(1)
            } else {
                return Err(e);
            }
        }
    }

    Ok(())
}
