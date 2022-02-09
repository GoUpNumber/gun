use crate::betting::*;
use bdk::bitcoin::{
    self, util::psbt::PartiallySignedTransaction as Psbt, Amount, OutPoint, Transaction, Txid,
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
            .map(|i| self.tx().input[*i as usize].previous_output)
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
            psbt_input
                .final_script_witness
                .get_or_insert(txin.witness.to_vec());
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

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state")]
pub enum BetState {
    /// You've made a proposal
    Proposed { local_proposal: LocalProposal },
    /// You've made an offer
    Offered {
        bet: OfferedBet,
        encrypted_offer: Ciphertext,
    },
    /// The bet tx has been included in mempool or chain
    Included {
        bet: Bet,
        // None implies in mempool
        height: Option<u32>,
    },
    /// You won the bet
    Won {
        bet: Bet,
        secret_key: bitcoin::secp256k1::SecretKey,
        attestation: Attestation,
    },
    /// You lost the bet
    Lost { bet: Bet, attestation: Attestation },
    /// A Tx spending the bet output has been included in mempool or chain.
    Claimed {
        bet: Bet,
        txid: Txid,
        // None implies calim tx is in mempool
        height: Option<u32>,
        secret_key: bitcoin::secp256k1::SecretKey,
        attestation: Attestation,
    },
    /// There is a tx spending one of the bet inputs that is *not* the bet tx.
    Canceled {
        pre_cancel: BetOrProp,
        bet_spent_vin: u32,
        cancel_txid: Txid,
        cancel_vin: u32,
        /// Height of cancel tx  None implies cancel tx is in mempool
        height: Option<u32>,
        /// Whether we intend to cancel the bet.
        i_intend_cancel: bool,
    },
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum BetOrProp {
    Bet(Bet),
    Proposal(LocalProposal),
    OfferedBet {
        bet: OfferedBet,
        encrypted_offer: Ciphertext,
    },
}

impl BetOrProp {
    pub fn inputs(&self) -> Vec<OutPoint> {
        match self {
            BetOrProp::Bet(bet)
            | BetOrProp::OfferedBet {
                bet: OfferedBet(bet),
                ..
            } => bet
                .tx()
                .input
                .iter()
                .map(|input| input.previous_output)
                .collect(),
            BetOrProp::Proposal(local_proposal) => local_proposal.proposal.inputs.clone(),
        }
    }
}

impl BetState {
    pub fn name(&self) -> &'static str {
        use BetState::*;
        match self {
            Proposed { .. } => "proposed",
            Offered { .. } => "offered",
            Included { height: None, .. } => "unconfirmed",
            Included {
                height: Some(_), ..
            } => "confirmed",
            Won { .. } => "won",
            Lost { .. } => "lost",
            Claimed { height: None, .. } => "claiming",
            Claimed {
                height: Some(_), ..
            } => "claimed",
            Canceled { height: None, .. } => "canceling",
            Canceled {
                height: Some(_), ..
            } => "canceled",
        }
    }

    pub fn reserved_utxos(&self) -> Vec<OutPoint> {
        use BetState::*;
        match self {
            Proposed { local_proposal } => local_proposal
                .proposal
                .inputs
                .iter()
                .map(Clone::clone)
                .collect(),
            Offered {
                bet: OfferedBet(bet),
                ..
            }
            | Included { bet, .. } => bet
                .my_input_indexes
                .iter()
                .map(|i| bet.tx().input[*i as usize].previous_output)
                .collect(),
            _ => vec![],
        }
    }

    pub fn into_bet_or_prop(self) -> BetOrProp {
        match self {
            BetState::Proposed { local_proposal } => BetOrProp::Proposal(local_proposal),
            BetState::Offered {
                bet,
                encrypted_offer,
            } => BetOrProp::OfferedBet {
                bet,
                encrypted_offer,
            },
            BetState::Canceled { pre_cancel, .. } => pre_cancel,
            BetState::Included { bet, .. }
            | BetState::Won { bet, .. }
            | BetState::Lost { bet, .. }
            | BetState::Claimed { bet, .. } => BetOrProp::Bet(bet),
        }
    }

    pub fn tags_mut(&mut self) -> &mut Vec<String> {
        match self {
            BetState::Proposed { local_proposal }
            | BetState::Canceled {
                pre_cancel: BetOrProp::Proposal(local_proposal),
                ..
            } => &mut local_proposal.tags,
            BetState::Offered {
                bet: OfferedBet(bet),
                ..
            }
            | BetState::Included { bet, .. }
            | BetState::Won { bet, .. }
            | BetState::Lost { bet, .. }
            | BetState::Claimed { bet, .. }
            | BetState::Canceled {
                pre_cancel:
                    BetOrProp::OfferedBet {
                        bet: OfferedBet(bet),
                        ..
                    }
                    | BetOrProp::Bet(bet),
                ..
            } => &mut bet.tags,
        }
    }

    pub fn relies_on_protocol_secret(&self) -> bool {
        match self {
            BetState::Proposed { .. } => true,
            _ => false,
        }
    }
}
