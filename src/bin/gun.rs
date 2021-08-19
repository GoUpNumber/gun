use gun_wallet::cmd::{self, bet::BetOpt, AddressOpt, InitOpt, SendOpt, TransactionOpt, UtxoOpt};
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
}

fn main() -> anyhow::Result<()> {
    let opt = Opt::from_args();
    let sync = opt.sync;

    let wallet_dir = opt.gun_dir.unwrap_or_else(|| {
        let mut default_dir = PathBuf::new();
        default_dir.push(&dirs::home_dir().unwrap());
        default_dir.push(".gun");
        default_dir
    });

    if sync {
        use Commands::*;

        if let Balance | Address(_) | Send(_) | Tx(_) | Utxo(_) = opt.command {
            let (wallet, _, _, config) = cmd::load_wallet(&wallet_dir)?;
            eprintln!("syncing wallet with {:?}", config.blockchain);
            wallet.sync(bdk::blockchain::noop_progress(), None)?;
        }

        // we poke bets to update balance from bets as well.
        if let Balance = opt.command {
            let party = cmd::load_party(&wallet_dir)?;
            party.poke_bets();
        }
    }

    let res = match opt.command {
        Commands::Bet(opt) => cmd::run_bet_cmd(&wallet_dir, opt, sync),
        Commands::Balance => cmd::run_balance(wallet_dir),
        Commands::Address(opt) => cmd::get_address(&wallet_dir, opt),
        Commands::Send(opt) => cmd::run_send(&wallet_dir, opt),
        Commands::Init(opt) => cmd::run_init(&wallet_dir, opt),
        Commands::Tx(opt) => cmd::run_transaction_cmd(&wallet_dir, opt),
        Commands::Utxo(opt) => cmd::run_utxo_cmd(&wallet_dir, opt),
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
            } else {
                if let Some(output) = output.render() {
                    println!("{}", output)
                }
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
