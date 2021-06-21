#![allow(non_snake_case)]
#![feature(string_remove_matches)]

use std::str::FromStr;

use bdk::bitcoin::Amount;
pub use bdk::{bitcoin};
pub mod amount_ext;
pub mod bet;
pub mod bet_database;
mod change;
pub mod cmd;
pub mod config;
pub mod ecdh;
pub mod encode;
mod fee_spec;
pub mod keychain;
pub mod party;
pub use fee_spec::*;
pub use reqwest;

pub use chacha20::cipher;
pub use olivia_core::{chrono, url};
pub use olivia_secp256k1::schnorr_fun::fun::{hex, rand_core};

pub type OracleInfo = olivia_core::OracleInfo<olivia_secp256k1::Secp256k1>;
pub type OracleEvent = olivia_core::OracleEvent<olivia_secp256k1::Secp256k1>;

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
