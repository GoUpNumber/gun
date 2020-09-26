use bweet::proposal::Proposal;
use magical::{
    bitcoin::{util::bip32::ExtendedPrivKey, Network},
    blockchain::EsploraBlockchain,
    cli, reqwest, sled, Wallet,
};

use clap::{Arg, SubCommand};
use std::{path::PathBuf, sync::Arc};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = cli::make_cli_subcommands()
        .subcommand(
            SubCommand::with_name("bet-propose")
                .about("Propose an event to bet on")
                .arg(Arg::with_name("event-id").required(true)),
        )
        .subcommand(
            SubCommand::with_name("bet-offer")
                .about("Make an offer in response to a proposal")
                .arg(Arg::with_name("proposal").required(true))
                .arg(Arg::with_name("odds").required(true)),
        );

    let matches = app.get_matches();
    let database = sled::open(prepare_home_dir()?.to_str().unwrap())?;
    let tree = database.open_tree("main")?;
    let esplora = EsploraBlockchain::new("http://localhost:3000");
    let seed = [42u8; 64];
    let xprv = ExtendedPrivKey::new_master(Network::Regtest, &seed)?;
    let descriptor =  "wpkh(xprv9s21ZrQH143K4CTb63EaMxja1YiTnSEWKMbn23uoEnAzxjdUJRQkazCAtzxGm4LSoTSVTptoV9RbchnKPW9HxKtZumdyxyikZFDLhogJ5Uj/44'/0'/0'/0/*)";
    // let descriptor = format!("wpkh({}/44'/0'/0'/0/*)", xprv);
    println!("{}", descriptor);
    let wallet = Wallet::new(&descriptor, None, Network::Regtest, tree, esplora).unwrap();
    let wallet = Arc::new(wallet);

    let result = if let Some(sub_args) = matches.subcommand_matches("bet-proposal") {
        let event_id = reqwest::Url::parse(sub_args.value_of("event-id").unwrap())?;
        let proposal = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(bweet::proposal::make_proposalment(
                &seed, &wallet, event_id, 100_000,
            ))
            .unwrap();
        proposal.to_string()
    } else if let Some(sub_args) = matches.subcommand_matches("bet-offer") {
        let proposal = Proposal::from_str(sub_args.value_of("proposal").unwrap())?;
        "tmp".to_string()
    } else {
        serde_json::to_string(&cli::handle_matches(wallet.clone().as_ref(), matches)?)?
    };

    println!("{}", result);
    Ok(())
}

fn prepare_home_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let mut dir = PathBuf::new();
    dir.push(&dirs::home_dir().unwrap());
    dir.push(".bweet");

    if !dir.exists() {
        println!("Creating database in {}", dir.as_path().display());
        std::fs::create_dir(&dir)?
    }

    dir.push("database.sled");
    Ok(dir)
}
