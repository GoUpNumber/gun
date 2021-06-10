use crate::{
    bet_database::{BetId, BetState},
    bitcoin::{Amount, Script},
    change::Change,
    keychain::KeyPair,
    party::Party,
};
use anyhow::{anyhow, Context};
use bdk::{bitcoin, bitcoin::Denomination, database::BatchDatabase, reqwest, FeeRate};
use core::str::FromStr;
use olivia_core::{EventId, OracleEvent, OracleId};
use olivia_secp256k1::{
    schnorr_fun::fun::{marker::*, Point},
    Secp256k1,
};

use super::BetArgs;

#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub enum PayloadVer {
    One(Payload),
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct Proposal {
    pub oracle: String,
    pub event_id: EventId,
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
    pub value: Amount,
    pub payload: Payload,
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct LocalProposal {
    pub proposal: Proposal,
    pub oracle_event: OracleEvent<Secp256k1>,
    pub keypair: KeyPair,
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct Payload {
    pub inputs: Vec<bdk::bitcoin::OutPoint>,
    pub public_key: Point<EvenY>,
    pub change: Option<Change>,
}

impl Proposal {
    pub fn to_string(&self) -> String {
        format!(
            "📣{}#{}#{}#{}",
            self.value
                .to_string_in(Denomination::Bitcoin)
                .trim_end_matches('0'),
            self.oracle,
            self.event_id,
            crate::encode::serialize_base2048(&PayloadVer::One(self.payload.clone()))
        )
    }

    pub fn from_str(string: &str) -> anyhow::Result<Self> {
        let string = string.trim_start_matches("📣");
        let mut segments = string.split("#");
        let value = Amount::from_str_in(
            segments.next().ok_or(anyhow!("missing amount"))?,
            Denomination::Bitcoin,
        )?;
        let oracle = segments
            .next()
            .ok_or(anyhow!("missing oralce"))?
            .to_string();
        let event_id = EventId::from_str(segments.next().ok_or(anyhow!("missing event id"))?)?;
        let base2048_encoded_payload = segments
            .next()
            .ok_or(anyhow!("missing base2048 encoded data"))?;
        let payload = match crate::encode::deserialize_base2048(base2048_encoded_payload)? {
            PayloadVer::One(payload) => payload,
        };

        Ok(Proposal {
            oracle,
            value,
            event_id,
            payload,
        })
    }

    pub fn to_sentence(&self) -> String {
        format!(
            "Wants to bet {} on {} relying on {} as the oracle",
            self.value, self.event_id, self.oracle
        )
    }
}

impl<D: BatchDatabase> Party<bdk::blockchain::EsploraBlockchain, D> {
    pub async fn make_proposal_from_url(
        &self,
        url: reqwest::Url,
        args: BetArgs<'_, '_>,
    ) -> anyhow::Result<(BetId, Proposal)> {
        let oracle_id = url.host_str().unwrap().to_string();
        let oracle_event = self.get_oracle_event_from_url(url).await?;
        self.save_oracle_info(oracle_id.clone()).await?;
        self.make_proposal(oracle_id, oracle_event, args)
    }

    pub fn make_proposal(
        &self,
        oracle_id: OracleId,
        oracle_event: OracleEvent<Secp256k1>,
        args: BetArgs,
    ) -> anyhow::Result<(BetId, Proposal)> {
        let event_id = &oracle_event.event.id;
        if !event_id.is_binary() {
            return Err(anyhow!(
                "Cannot make a bet on {} since it isn't binary",
                event_id
            ));
        }
        let keypair = self.keychain.keypair_for_proposal(&event_id, 0);

        let mut builder = self.wallet.build_tx();
        builder
            .fee_rate(FeeRate::from_sat_per_vb(0.0))
            .add_recipient(Script::default(), args.value.as_sat());

        args.apply_args(self.bet_db(), &mut builder)?;

        let (psbt, txdetails) = builder
            .finish()
            .context("Failed to gather proposal outputs")?;

        assert_eq!(txdetails.fees, 0);

        let outputs = &psbt.global.unsigned_tx.output;
        let tx_inputs = psbt
            .global
            .unsigned_tx
            .input
            .iter()
            .map(|txin| txin.previous_output.clone())
            .collect();

        let change = if outputs.len() > 1 {
            if outputs.len() != 2 {
                return Err(anyhow!(
                    "wallet produced psbt with too many outputs: {:?}",
                    psbt
                ));
            }
            Some(
                outputs
                    .iter()
                    .find_map(|output| {
                        if output.script_pubkey != Script::default() {
                            Some(Change::new(output.value, output.script_pubkey.clone()))
                        } else {
                            None
                        }
                    })
                    .unwrap(),
            )
        } else {
            None
        };

        let proposal = Proposal {
            oracle: oracle_id.clone(),
            event_id: event_id.clone(),
            value: args.value,
            payload: Payload {
                inputs: tx_inputs,
                public_key: keypair.public_key,
                change,
            },
        };

        let local_proposal = LocalProposal {
            proposal: proposal.clone(),
            oracle_event,
            keypair,
        };

        let new_bet = BetState::Proposed { local_proposal };
        let bet_id = self.bet_db.insert_bet(new_bet)?;

        Ok((bet_id, proposal))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bdk::bitcoin::{hashes::Hash, Address, OutPoint, Txid};
    use olivia_secp256k1::schnorr_fun::fun::{s, G};

    #[test]
    fn to_and_from_str() {
        let forty_two = Point::<EvenY>::from_scalar_mul(G, &mut s!(42));
        let change_address =
            Address::from_str("bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej")
                .unwrap();
        let mut proposal = Proposal {
            oracle: "h00.ooo".into(),
            value: Amount::from_str("0.1 BTC").unwrap(),
            event_id: EventId::from_str("/random/2020-09-25T08:00:00/heads_tails.win").unwrap(),
            payload: Payload {
                inputs: vec![
                    OutPoint::new(Txid::from_slice(&[1u8; 32]).unwrap(), 0),
                    OutPoint::new(Txid::from_slice(&[2u8; 32]).unwrap(), 1),
                ],
                public_key: forty_two,
                change: None,
            },
        };

        let encoded = proposal.to_string();
        let decoded = Proposal::from_str(&encoded).unwrap();
        assert_eq!(decoded, proposal);

        proposal.payload.change = Some(Change::new(100_000, change_address.script_pubkey()));

        let encoded = proposal.to_string();
        let decoded = Proposal::from_str(&encoded).unwrap();
        assert_eq!(decoded, proposal);
    }
}
