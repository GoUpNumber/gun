mod fund_wallet;
mod init;
pub use init::*;
pub mod bet;
pub mod dev;

use crate::config::Config;
use anyhow::anyhow;
use std::{fs, path::PathBuf};

pub fn get_config(wallet_dir: &PathBuf) -> anyhow::Result<Config> {
    let mut config_file = wallet_dir.clone();
    config_file.push("config.json");

    match config_file.exists() {
        true => {
            let json_config = fs::read_to_string(config_file.clone())?;
            Ok(serde_json::from_str::<Config>(&json_config)?)
        }
        false => {
            return Err(anyhow!(
                "missing config file at {}",
                config_file.as_path().display()
            ))
        }
    }
}
