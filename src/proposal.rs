use crate::{
    bitcoin::{Amount, Script},
    change::Change,
    keychain::Keychain,
};
use anyhow::anyhow;
use bdk::{
    bitcoin::Denomination, blockchain::Blockchain, database::BatchDatabase, reqwest,
    wallet::coin_selection::DumbCoinSelection, FeeRate, TxBuilder, Wallet,
};
use core::str::FromStr;
use olivia_core::{http::EventResponse, EventId};
use olivia_secp256k1::{
    schnorr_fun::fun::{marker::*, Point},
    Secp256k1,
};

#[derive(Debug, Clone, PartialEq)]
pub struct Proposal {
    pub oracle: String,
    pub event_id: EventId,
    pub value: Amount,
    pub payload: Payload,
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
            "PROPOSE#{}#{}#{}#{}",
            self.value
                .to_string_in(Denomination::Bitcoin)
                .trim_end_matches('0'),
            self.oracle,
            self.event_id,
            crate::encode::serialize(&self.payload)
        )
    }

    pub fn from_str(string: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut segments = string.split("#");
        if segments.next() != Some("PROPOSE") {
            return Err("not a proposal")?;
        }
        let value = Amount::from_str_in(
            segments.next().ok_or("missing amount")?,
            Denomination::Bitcoin,
        )?;
        let oracle = segments.next().ok_or("missing oralce")?.to_string();
        let event_id = EventId::from_str(segments.next().ok_or("missing event id")?)?;
        let base2048_encoded_payload = segments.next().ok_or("missing base2048 encoded data")?;
        let payload = crate::encode::deserialize(base2048_encoded_payload)?;

        Ok(Proposal {
            oracle,
            value,
            event_id,
            payload,
        })
    }
}

pub async fn make_proposal(
    keychain: &Keychain,
    wallet: &Wallet<impl Blockchain, impl BatchDatabase>,
    url: reqwest::Url,
    value: Amount,
) -> anyhow::Result<Proposal> {
    let event_response = reqwest::get(url.clone())
        .await?
        .json::<EventResponse<Secp256k1>>()
        .await
        .map_err(|_e| {
            anyhow!(
                "URL ({}) did not return a valid JSON event description",
                &url
            )
        })?;
    let event_id = event_response.id;

    let keypair = keychain.keypair_for_proposal(&event_id, 0);

    let builder = TxBuilder::default()
        .fee_rate(FeeRate::from_sat_per_vb(0.0))
        .add_recipient(Script::default(), value.as_sat());

    let (psbt, txdetails) = wallet.create_tx::<DumbCoinSelection>(builder)?;
    assert_eq!(txdetails.fees, 0);

    let outputs = &psbt.global.unsigned_tx.output;
    let inputs = psbt
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

    Ok(Proposal {
        oracle: url.host().unwrap().to_string(),
        event_id,
        value: value,
        payload: Payload {
            inputs,
            public_key: keypair.public_key,
            change,
        },
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use bdk::bitcoin::{hashes::Hash, Address, OutPoint, Txid};
    use olivia_secp256k1::schnorr_fun::fun::{s, XOnly, G};

    #[test]
    fn to_and_from_str() {
        let forty_two = Point::<EvenY>::from_scalar_mul(G, &mut s!(42));
        let change_address =
            Address::from_str("bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej")
                .unwrap();
        let mut proposal = Proposal {
            oracle: "h00.ooo".into(),
            value: Amount::from_str("0.1 BTC").unwrap(),
            event_id: EventId::from_str("/random/2020-09-25T08:00:00/heads_tails?left-win")
                .unwrap(),
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
        dbg!(&encoded);
        let decoded = Proposal::from_str(&encoded).unwrap();
        assert_eq!(decoded, proposal);

        proposal.payload.change = Some(Change::new(100_000, change_address.script_pubkey()));

        let encoded = proposal.to_string();
        dbg!(&encoded);
        let decoded = Proposal::from_str(&encoded).unwrap();
        assert_eq!(decoded, proposal);
    }
}
