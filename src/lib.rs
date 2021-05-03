#![allow(non_snake_case)]

pub use bdk::{bitcoin, reqwest};
pub mod amount_ext;
pub mod bet_database;
mod change;
pub mod cmd;
pub mod config;
pub mod ecdh;
pub mod encode;
pub mod keychain;
pub mod party;
pub mod bet;

pub use chacha20::cipher;
pub use olivia_secp256k1::schnorr_fun::fun::rand_core;
pub use olivia_core::chrono;

pub type OracleInfo = olivia_core::OracleInfo<olivia_secp256k1::Secp256k1>;
