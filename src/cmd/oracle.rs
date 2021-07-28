use crate::{bet_database::BetDatabase, cmd, item, reqwest, OracleInfo, Url};
use anyhow::anyhow;
use olivia_core::{http::RootResponse, OracleId};
use olivia_secp256k1::Secp256k1;
use std::str::FromStr;

use super::{Cell, CmdOutput};

#[derive(structopt::StructOpt, Debug, Clone)]
/// Oracle commands
pub enum OracleOpt {
    /// Trust a new oracle
    Add {
        /// The base url of the oracle e.g. https://h00.ooo
        url: String,
        /// Automatically confirm trust
        #[structopt(short, long)]
        yes: bool,
    },
    /// List oracles
    List,
    /// Remove an oracle from the list of trusted oracles
    Remove {
        /// The oralce's id
        oracle_id: OracleId,
    },
    /// Show information about an oracle
    Show {
        /// The oracle's id
        oracle_id: OracleId,
    },
}

pub fn run_oralce_cmd(bet_db: BetDatabase, cmd: OracleOpt) -> anyhow::Result<CmdOutput> {
    match cmd {
        OracleOpt::Add { url, yes } => {
            let url =
                Url::from_str(&url).or_else(|_| Url::from_str(&format!("https://{}", url)))?;
            let oracle_id = url
                .host()
                .ok_or(anyhow!("orcale url missing host"))?
                .to_string();
            match bet_db.get_entity::<OracleInfo>(oracle_id.clone())? {
                Some(_) => eprintln!("oracle {} is already trusted", oracle_id),
                None => {
                    let root_response = reqwest::blocking::get(url)?
                        .error_for_status()?
                        .json::<RootResponse<Secp256k1>>()?;
                    let oracle_info = OracleInfo {
                        id: oracle_id,
                        oracle_keys: root_response.public_keys,
                    };

                    println!("{}", serde_json::to_string_pretty(&oracle_info).unwrap());

                    if yes || cmd::read_answer(format!("Trust the oracle displayed above")) {
                        bet_db.insert_oracle_info(oracle_info.clone())?;
                    }
                }
            }

            Ok(CmdOutput::None)
        }
        OracleOpt::List => {
            let oracles = bet_db.list_entities_print_error::<OracleInfo>();
            let mut rows = vec![];

            for (oracle_id, oracle_info) in oracles {
                let oracle_keys = oracle_info.oracle_keys;
                rows.push(vec![
                    Cell::String(oracle_id),
                    Cell::String(oracle_keys.attestation_key.to_string()),
                    Cell::String(oracle_keys.announcement_key.to_string()),
                ]);
            }
            Ok(CmdOutput::table(
                vec!["id", "attestation-key", "announcement-key"],
                rows,
            ))
        }
        OracleOpt::Remove { oracle_id } => {
            if bet_db
                .remove_entity::<OracleInfo>(oracle_id.clone())?
                .is_none()
            {
                return Err(anyhow!("oralce '{}' doesn't exist", oracle_id));
            }
            Ok(CmdOutput::None)
        }
        OracleOpt::Show { oracle_id } => {
            let oracle_info = bet_db
                .get_entity::<OracleInfo>(oracle_id.clone())?
                .ok_or(anyhow!("Oracle {} not in database", oracle_id))?;
            let oracle_keys = oracle_info.oracle_keys;

            Ok(item! {
                "id" => Cell::string(oracle_id),
                "attestation-key" => Cell::string(oracle_keys.attestation_key),
                "announcement-key" => Cell::string(oracle_keys.announcement_key)
            })
        }
    }
}
