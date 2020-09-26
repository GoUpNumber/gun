use crate::{
    bitcoin::{hashes::Hash, OutPoint, Script, Txid},
    change::Change,
};
use core::str::FromStr;
use magical::{
    blockchain::Blockchain, database::BatchDatabase, reqwest,
    wallet::coin_selection::DumbCoinSelection, FeeRate, TxBuilder, Wallet,
};
use olivia_core::{http::EventResponse, EventId};
use olivia_secp256k1::{schnorr_fun::fun::XOnly, Secp256k1};

#[derive(Debug, Clone, PartialEq)]
pub struct Proposal {
    pub oracle: String,
    pub event_id: EventId,
    pub payload: Payload,
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct Payload {
    pub inputs: Vec<magical::bitcoin::OutPoint>,
    pub public_key: XOnly,
    pub change: Option<Change>,
}

impl Proposal {
    pub fn to_string(&self) -> String {
        format!(
            "PROPOSE!{}!{}!{}",
            self.oracle,
            self.event_id,
            base2048::encode(bincode::serialize(&self.payload).unwrap().as_ref())
        )
    }

    pub fn from_str(string: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut segments = string.split("!");
        if segments.next() != Some("PROPOSE") {
            return Err("not a proposal")?;
        }
        let oracle = segments.next().ok_or("missing oralce")?.to_string();
        let event_id = EventId::from_str(segments.next().ok_or("missing event id")?)?;
        let base2048_encoded = segments.next().ok_or("missing base2048 encoded data")?;
        let binary = base2048::decode(base2048_encoded).ok_or("invalid base2048 encoding")?;
        let payload = bincode::deserialize::<Payload>(&binary[..])?;

        Ok(Proposal {
            oracle,
            event_id,
            payload,
        })
    }
}

pub async fn make_proposalment(
    seed: &[u8; 64],
    wallet: &Wallet<impl Blockchain, impl BatchDatabase>,
    url: reqwest::Url,
    value: u64,
) -> Result<Proposal, Box<dyn std::error::Error>> {
    let event_response = reqwest::get(url.clone())
        .await?
        .json::<EventResponse<Secp256k1>>()
        .await
        .map_err(|_e| {
            format!(
                "URL ({}) did not return a valid JSON event description",
                &url
            )
        })?;
    let event_id = event_response.id;

    let keypair = crate::kdf::kdf(seed, &event_id, value, 0);

    let builder = TxBuilder::default()
        .fee_rate(FeeRate::from_sat_per_vb(0.0))
        .add_recipient(Script::default(), value);

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
    let change_script = if outputs.len() == 2 {
        Some(outputs[1].script_pubkey.clone())
    } else {
        None
    };

    Ok(Proposal {
        oracle: url.host().unwrap().to_string(),
        event_id,
        payload: Payload {
            inputs,
            public_key: keypair.public_key,
            change: change_script.map(|script| Change::new(value, script)),
        },
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use magical::bitcoin::Address;
    use olivia_secp256k1::schnorr_fun::fun::{s, G};

    #[test]
    fn to_and_from_str() {
        let forty_two = XOnly::from_scalar_mul(G, &mut s!(42));
        let change_address =
            Address::from_str("bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej")
                .unwrap();
        let mut proposal = Proposal {
            oracle: "h00.ooo".into(),
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
        panic!()
    }
}
