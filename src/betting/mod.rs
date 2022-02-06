mod bet;
mod bet_args;
mod joint_output;
mod offer;
mod proposal;
mod randomize;
mod wallet_impls;
mod witness;

pub use bet::*;
pub use bet_args::*;
pub use joint_output::*;
pub use offer::*;
use olivia_secp256k1::fun::{marker::EvenY, Point};
pub use proposal::*;
pub use randomize::*;
pub use witness::*;

pub type OracleEvent = olivia_core::OracleEvent<olivia_secp256k1::Secp256k1>;
pub type Attestation = olivia_core::Attestation<olivia_secp256k1::Secp256k1>;
pub type EventResponse = olivia_core::http::EventResponse<olivia_secp256k1::Secp256k1>;

pub type PublicKey = Point<EvenY>;
pub type BetId = u32;
