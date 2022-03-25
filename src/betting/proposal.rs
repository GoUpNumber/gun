use std::str::FromStr;

use crate::{
    betting::*,
    change::{BinScript, Change},
};
use anyhow::anyhow;
use bdk::bitcoin::{self, Amount};
use olivia_core::EventId;

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub enum VersionedProposal {
    One(Proposal),
}

impl From<VersionedProposal> for Proposal {
    fn from(vp: VersionedProposal) -> Self {
        match vp {
            VersionedProposal::One(proposal) => proposal,
        }
    }
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct Proposal {
    pub oracle: String,
    pub event_id: EventId,
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
    pub value: Amount,
    pub inputs: Vec<bdk::bitcoin::OutPoint>,
    pub public_key: Point<EvenY>,
    pub change_script: Option<BinScript>,
}

impl Proposal {
    pub fn into_versioned(self) -> VersionedProposal {
        VersionedProposal::One(self)
    }
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct LocalProposal {
    pub proposal: Proposal,
    pub oracle_event: OracleEvent,
    pub change: Option<Change>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct Payload {
    pub public_key: Point<EvenY>,
    pub inputs: Vec<bdk::bitcoin::OutPoint>,
    pub change_script: Option<BinScript>,
}

impl Proposal {
    pub fn to_sentence(&self) -> String {
        format!(
            "Wants to bet {} on {} relying on {} as the oracle",
            self.value, self.event_id, self.oracle
        )
    }
}

impl core::fmt::Display for VersionedProposal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VersionedProposal::One(proposal) => {
                let payload = Payload {
                    inputs: proposal.inputs.clone(),
                    public_key: proposal.public_key,
                    change_script: proposal.change_script.clone(),
                };
                write!(
                    f,
                    "{}#{}#{}#{}",
                    proposal
                        .value
                        .to_string_in(bitcoin::Denomination::Bitcoin)
                        // FIXME: This looks dangerous?
                        .trim_end_matches('0'),
                    proposal.oracle,
                    proposal.event_id,
                    crate::encode::serialize_base2048(&payload)
                )
            }
        }
    }
}

impl FromStr for VersionedProposal {
    type Err = anyhow::Error;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let mut segments = string.split('#');
        let value = Amount::from_str_in(
            segments.next().ok_or(anyhow!("missing amount"))?,
            bitcoin::Denomination::Bitcoin,
        )?;
        let oracle = segments
            .next()
            .ok_or(anyhow!("missing oralce"))?
            .to_string();
        let event_id = EventId::from_str(segments.next().ok_or(anyhow!("missing event id"))?)?;
        let base2048_encoded_payload = segments
            .next()
            .ok_or(anyhow!("missing base2048 encoded data"))?;

        let payload: Payload = crate::encode::deserialize_base2048(base2048_encoded_payload)?;

        Ok(VersionedProposal::One(Proposal {
            oracle,
            value,
            event_id,
            inputs: payload.inputs,
            public_key: payload.public_key,
            change_script: payload.change_script,
        }))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bdk::bitcoin::{hashes::Hash, Address, OutPoint, Txid};
    use olivia_secp256k1::schnorr_fun::fun::{s, G};

    #[test]
    fn to_and_from_str() {
        use std::string::ToString;
        let forty_two = Point::<EvenY>::from_scalar_mul(G, &mut s!(42));
        let change_address =
            Address::from_str("bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej")
                .unwrap();
        let mut proposal = Proposal {
            oracle: "h00.ooo".into(),
            value: Amount::from_str("0.1 BTC").unwrap(),
            event_id: EventId::from_str("/random/2020-09-25T08:00:00/heads_tails.winner").unwrap(),
            inputs: vec![
                OutPoint::new(Txid::from_slice(&[1u8; 32]).unwrap(), 0),
                OutPoint::new(Txid::from_slice(&[2u8; 32]).unwrap(), 1),
            ],
            public_key: forty_two,
            change_script: None,
        };

        let encoded = proposal.clone().into_versioned().to_string();
        let decoded = VersionedProposal::from_str(&encoded).unwrap();
        assert_eq!(proposal, decoded.into());

        proposal.change_script = Some(change_address.script_pubkey().into());

        let encoded = proposal.clone().into_versioned().to_string();
        let decoded = VersionedProposal::from_str(&encoded).unwrap();
        assert_eq!(proposal, decoded.into());
    }

    #[test]
    fn to_and_from_string_fixed() {
        // so we don't accidentally break parsing
        use bdk::bitcoin::Address;
        use std::str::FromStr;
        let fixed = VersionedProposal::One(Proposal {
            oracle: "h00.ooo".into(),
            event_id: EventId::from_str("/EPL/match/2021-08-22/ARS_CHE.vs=CHE_win").unwrap(),
            value: Amount::from_str("0.01000000 BTC").unwrap(),
            inputs: vec![OutPoint::from_str(
                "d407fe2bd55b6076ce4c78028dc95b4097dd1e5acbf6ccaa741559a0903f1565:1",
            )
            .unwrap()],
            public_key: Point::from_str(
                "119cfc5a4dd8cffeebe9cfb1b42ef3d46d2dc38decebc67826d33ec8d44030c0",
            )
            .unwrap(),
            change_script: Some(
                Address::from_str("bc1qvkswtx2t4y8t6237q753htu4hl4mxm5a9swfjw")
                    .unwrap()
                    .script_pubkey()
                    .into(),
            ),
        });

        let string =  "0.01#h00.ooo#/EPL/match/2021-08-22/ARS_CHE.vs=CHE_win#Ō࿃Ŵઝঢჰ௵ʏఒଊಫ୵ช༨ɽબവഉబ٧থǀചµǃȅАǊëঌฉѝႡѧ८ಜԺȯǱ૭զӌભഅಮਫႫႿÅąउȆѡԯӂՃĵ࿐ৠĺ৷เшრఠՁ༎";
        assert_eq!(VersionedProposal::from_str(string).unwrap(), fixed);
        assert_eq!(fixed.to_string(), string);
    }
}
