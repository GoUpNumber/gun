use crate::party::JointOutput;
use bdk::bitcoin::{
    self, util::psbt::PartiallySignedTransaction as Psbt, Amount, OutPoint, Transaction,
};
use olivia_core::{OracleEvent, OracleId, Outcome};
use olivia_secp256k1::Secp256k1;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Bet {
    pub psbt: Psbt,
    pub my_input_indexes: Vec<u32>,
    pub vout: u32,
    pub joint_output: JointOutput,
    pub oracle_id: OracleId,
    pub oracle_event: OracleEvent<Secp256k1>,
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
    pub local_value: Amount,
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
    pub joint_output_value: Amount,
    pub i_chose_right: bool,
    #[serde(default)]
    pub tags: Vec<String>,
}

impl Bet {
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

    pub fn input_outpoints(&self) -> Vec<OutPoint> {
        self.psbt
            .global
            .unsigned_tx
            .input
            .iter()
            .map(|x| x.previous_output)
            .collect()
    }
}

/// newtype to mark a bet that doesn't have all its PSBT inputs signed
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct OfferedBet(pub Bet);

impl OfferedBet {
    pub fn add_counterparty_sigs(self, tx: Transaction) -> Bet {
        let mut bet = self.0;
        assert_eq!(
            tx.txid(),
            bet.tx().txid(),
            "the transactions must be the same to add_counterparty_sigs"
        );
        for (txin, psbt_input) in tx.input.into_iter().zip(bet.psbt.inputs.iter_mut()) {
            psbt_input.final_script_witness.get_or_insert(txin.witness);
        }

        bet
    }
}

impl std::ops::Deref for OfferedBet {
    type Target = Bet;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
