use anyhow::{anyhow, Context};
use bdk::{
    bitcoin::Network, blockchain::EsploraBlockchain, database::BatchDatabase, wallet::AddressIndex,
    Wallet,
};
use serde_json::json;
use std::{fs, path::PathBuf, process::Command};

pub fn nigiri_fund(
    wallet: &Wallet<EsploraBlockchain, impl BatchDatabase>,
) -> anyhow::Result<()> {
    let new_address = wallet.get_address(AddressIndex::New)?.address;
    println!("funding: {}", new_address);
    crate::reqwest::blocking::Client::new()
        .post("http://localhost:3000/faucet")
        .json(&json!({ "address": new_address }))
        .send()
        .context("Unable to contact nigiri")?;
    Ok(())
}

pub fn nigiri_start() -> anyhow::Result<()> {
    Command::new("nigiri").args(&["start"]).spawn()?.wait()?;
    Ok(())
}

pub fn nigiri_delete() -> anyhow::Result<()> {
    Command::new("nigiri")
        .args(&["stop", "--delete"])
        .spawn()?
        .wait()?;
    Ok(())
}

pub fn nigiri_stop() -> anyhow::Result<()> {
    Command::new("nigiri").args(&["stop"]).spawn()?.wait()?;
    Ok(())
}

pub fn reset(wallet_dir: &PathBuf) -> anyhow::Result<()> {
    let config = crate::cmd::load_config(&wallet_dir)?;
    if config.network != Network::Regtest {
        return Err(anyhow!(
            "Can delete a {} wallet (only regtest)",
            config.network
        ));
    }
    let mut db_file = wallet_dir.clone();
    db_file.push("database.sled");
    println!("Deleting {}", db_file.as_path().display());
    fs::remove_dir_all(db_file)?;
    Ok(())
}
