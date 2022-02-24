#![allow(non_snake_case, clippy::or_fun_call, clippy::vec_init_then_push)]

use std::str::FromStr;

use bdk::bitcoin::Amount;
pub mod amount_ext;
pub mod betting;
mod change;
pub mod cmd;
pub mod config;
pub mod ecdh;
pub mod encode;
mod fee_spec;
pub mod keychain;
pub mod psbt_ext;
pub mod signers;
pub use fee_spec::*;
pub mod bip85;
pub mod database;
mod serde_hacks;
pub mod wallet;

pub use chacha20::cipher;
pub use olivia_core::chrono;
pub use olivia_secp256k1::schnorr_fun::fun::{hex, rand_core};
pub use url::Url;

pub type OracleInfo = olivia_core::OracleInfo<olivia_secp256k1::Secp256k1>;

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
    (*olivia_secp256k1::fun::G)
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
