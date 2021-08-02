use crate::party::JointOutput;
use bdk::bitcoin::{self, Amount, OutPoint, Transaction};
use olivia_core::{OracleEvent, OracleId};
use olivia_secp256k1::Secp256k1;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Bet {
    pub tx: Transaction,
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
    pub fn prompt(&self) -> String {
        use core::fmt::Write;
        let mut res = String::new();
        let parties = self
            .oracle_event
            .event
            .id
            .parties()
            .expect("We only do vs type events");
        let (i_back, they_back) = match self.i_chose_right {
            false => parties,
            true => (parties.1, parties.0),
        };
        let i_risk = self.local_value;
        let i_gain = self.joint_output_value - self.local_value;
        let oracle = &self.oracle_id;
        let expected_outcome_time = self.oracle_event.event.expected_outcome_time;

        write!(
            &mut res,
            "You are betting on {}",
            self.oracle_event.event.id
        )
        .unwrap();
        write!(&mut res, "\n").unwrap();
        write!(&mut res, "You win if {} beats {}.", i_back, they_back).unwrap();
        write!(&mut res, "\n").unwrap();
        write!(&mut res, "You risk {} to gain {}.", i_risk, i_gain).unwrap();
        write!(&mut res, "\n").unwrap();
        write!(&mut res, "The outcome is decided by {}.", oracle).unwrap();
        if let Some(time) = expected_outcome_time {
            write!(
                &mut res,
                "\nThe outcome is expected to be known at {}",
                time
            )
            .unwrap();
        }
        res
    }

    /// Get a mutable reference to the bet's joint output value.
    pub fn joint_output_value_mut(&mut self) -> &mut Amount {
        &mut self.joint_output_value
    }

    pub fn outpoint(&self) -> OutPoint {
        OutPoint {
            txid: self.tx.txid(),
            vout: self.vout,
        }
    }

    pub fn my_inputs(&self) -> Vec<OutPoint> {
        self.my_input_indexes
            .iter()
            .map(|i| self.tx.input[*i as usize].previous_output.clone())
            .collect()
    }
}
