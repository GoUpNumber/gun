use crate::party::JointOutput;
use bdk::bitcoin::{
    self, util::psbt::PartiallySignedTransaction as Psbt, Amount, OutPoint, Transaction,
};
use olivia_core::{OracleEvent, OracleId, Outcome};
use olivia_secp256k1::Secp256k1;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Bet {
    pub psbt: Psbt,
    pub my_input_indexes: Vec<usize>,
    pub vout: u32,
    pub joint_output: JointOutput,
    pub oracle_id: OracleId,
    pub oracle_event: OracleEvent<Secp256k1>,
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
    pub local_value: Amount,
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
    pub joint_output_value: Amount,
    pub i_chose_right: bool,
}

impl Bet {
    /// Get a mutable reference to the bet's joint output value.
    pub fn joint_output_value_mut(&mut self) -> &mut Amount {
        &mut self.joint_output_value
    }

    pub fn outpoint(&self) -> OutPoint {
        OutPoint {
            txid: self.tx().txid(),
            vout: self.vout,
        }
    }
    pub fn my_inputs(&self) -> Vec<OutPoint> {
        self.my_input_indexes
            .iter()
            .map(|i| self.tx().input[*i as usize].previous_output.clone())
            .collect()
    }

    pub fn tx(&self) -> Transaction {
        self.psbt.clone().extract_tx()
    }

    pub fn my_outcome(&self) -> Outcome {
        Outcome {
            id: self.oracle_event.event.id.clone(),
            value: self.i_chose_right as u64,
        }
    }
}
