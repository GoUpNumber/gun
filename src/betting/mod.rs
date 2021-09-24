mod bet;
mod database;
mod joint_output;
mod offer;
mod party;
mod proposal;
mod randomize;
mod witness;

pub use bet::*;
pub use database::*;
pub use joint_output::*;
pub use offer::*;
use olivia_secp256k1::fun::{marker::EvenY, Point};
pub use party::*;
pub use proposal::*;
pub use randomize::*;
pub use witness::*;

pub type OracleInfo = olivia_core::OracleInfo<olivia_secp256k1::Secp256k1>;
pub type OracleEvent = olivia_core::OracleEvent<olivia_secp256k1::Secp256k1>;
pub type Attestation = olivia_core::Attestation<olivia_secp256k1::Secp256k1>;
pub type EventResponse = olivia_core::http::EventResponse<olivia_secp256k1::Secp256k1>;

pub type PublicKey = Point<EvenY>;
