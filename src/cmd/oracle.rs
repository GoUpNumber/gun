use crate::{cmd, database::GunDatabase, elog, item, OracleInfo, Url};
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

pub fn run_oralce_cmd(gun_db: &GunDatabase, cmd: OracleOpt) -> anyhow::Result<CmdOutput> {
    match cmd {
        OracleOpt::Add { url, yes } => {
            let url =
                Url::from_str(&url).or_else(|_| Url::from_str(&format!("https://{}", url)))?;
            let oracle_id = url
                .host()
                .ok_or(anyhow!("Oracle url missing host"))?
                .to_string();
            match gun_db.get_entity::<OracleInfo>(oracle_id.clone())? {
                Some(_) => {
                    elog!(@info "Oracle {} is already trusted", oracle_id);
                }
                None => {
                    let root_response = ureq::get(url.as_str())
                        .call()?
                        .into_json::<RootResponse<Secp256k1>>()?;
                    let oracle_info = OracleInfo {
                        id: oracle_id.clone(),
                        oracle_keys: root_response.public_keys,
                    };

                    println!("{}", serde_json::to_string_pretty(&oracle_info).unwrap());

                    if yes || cmd::read_yn("Trust the oracle displayed above") {
                        gun_db.insert_entity(oracle_id, oracle_info)?;
                    }
                }
            }

            Ok(CmdOutput::None)
        }
        OracleOpt::List => {
            let oracles = gun_db.list_entities_print_error::<OracleInfo>();
            let mut rows = vec![];

            for (oracle_id, oracle_info) in oracles {
                let oracle_keys = oracle_info.oracle_keys;
                rows.push(vec![
                    Cell::String(oracle_id),
                    Cell::string(oracle_keys.announcement),
                    Cell::string(oracle_keys.olivia_v1.is_some()),
                    Cell::string(oracle_keys.ecdsa_v1.is_some()),
                ]);
            }
            Ok(CmdOutput::table(
                vec!["id", "attestation-key", "olivia-v1", "ecdsa-v1"],
                rows,
            ))
        }
        OracleOpt::Remove { oracle_id } => {
            if gun_db
                .remove_entity::<OracleInfo>(oracle_id.clone())?
                .is_none()
            {
                return Err(anyhow!("oralce '{}' doesn't exist", oracle_id));
            }
            Ok(CmdOutput::None)
        }
        OracleOpt::Show { oracle_id } => {
            let oracle_info = gun_db
                .get_entity::<OracleInfo>(oracle_id.clone())?
                .ok_or(anyhow!("Oracle {} not in database", oracle_id))?;
            let oracle_keys = oracle_info.oracle_keys;

            Ok(item! {
                "id" => Cell::string(oracle_id),
                "olivia-v1-key" => oracle_keys.olivia_v1.map(Cell::string).unwrap_or(Cell::Empty),
                "ecdsa-v1-key" => oracle_keys.ecdsa_v1.map(Cell::string).unwrap_or(Cell::Empty),
                "announcement" => Cell::string(oracle_keys.announcement),
            })
        }
    }
}
