#![allow(non_snake_case)]

use std::str::FromStr;

pub use bdk::bitcoin;
use bdk::bitcoin::Amount;
pub mod amount_ext;
pub mod bet;
pub mod bet_database;
mod change;
pub mod ciphertext;
pub mod cmd;
pub mod config;
pub mod ecdh;
pub mod encode;
mod fee_spec;
pub mod keychain;
pub mod party;
pub mod psbt_ext;
pub use fee_spec::*;
pub use reqwest;

pub use chacha20::cipher;
pub use olivia_core::chrono;
pub use olivia_secp256k1::schnorr_fun::fun::{hex, rand_core};
pub use reqwest::Url;

pub type OracleInfo = olivia_core::OracleInfo<olivia_secp256k1::Secp256k1>;
pub type OracleEvent = olivia_core::OracleEvent<olivia_secp256k1::Secp256k1>;
pub type Attestation = olivia_core::Attestation<olivia_secp256k1::Secp256k1>;
pub type EventResponse = olivia_core::http::EventResponse<olivia_secp256k1::Secp256k1>;

#[derive(Clone, Debug)]
pub enum ValueChoice {
    All,
    Amount(Amount),
}

impl FromStr for ValueChoice {
    type Err = anyhow::Error;

    fn from_str(string: &str) -> anyhow::Result<Self> {
        Ok(match string {
            "all" => ValueChoice::All,
            amount => {
                ValueChoice::Amount(<Amount as amount_ext::FromCliStr>::from_cli_str(amount)?)
            }
        })
    }
}

/// So we can use data structs to derive a key to be placed into them afterwards
pub(crate) fn placeholder_point(
) -> olivia_secp256k1::fun::Point<olivia_secp256k1::fun::marker::EvenY> {
    use olivia_secp256k1::fun::marker::*;
    olivia_secp256k1::fun::G
        .clone()
        .mark::<Normal>()
        .into_point_with_even_y()
        .0
}

pub fn format_dt_diff_till_now(dt: chrono::NaiveDateTime) -> String {
    let now = chrono::Utc::now().naive_utc();
    let diff = dt - now;
    if diff.abs() < chrono::Duration::hours(1) {
        format!("{}m", diff.num_minutes())
    } else if diff.abs() < chrono::Duration::days(1) {
        format!("{}h", diff.num_hours())
    } else {
        format!("{}d", diff.num_days())
    }
}
