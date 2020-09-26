use crate::bitcoin::{hashes::Hash, OutPoint, Script, Txid};
use core::str::FromStr;
use olivia_core::{EventId, http::EventResponse};
use magical::{Wallet, blockchain::Blockchain, database::BatchDatabase, reqwest, TxBuilder, FeeRate, wallet::coin_selection::DumbCoinSelection};
use olivia_secp256k1::{schnorr_fun::fun::XOnly, Secp256k1};

#[derive(Debug, Clone, PartialEq)]
pub struct Proposal {
    pub oracle: String,
    pub event_id: EventId,
    pub inputs: Vec<magical::bitcoin::OutPoint>,
    pub public_key: XOnly,
    pub change: Option<(u64, Script)>,
}

impl Proposal {
    pub fn to_string(&self) -> String {
        let mut binary = vec![];
        binary.push(0x00);
        binary.push(self.inputs.len() as u8);

        for input in self.inputs.iter() {
            binary.push(input.vout as u8);
            binary.extend(input.txid.as_ref());
        }

        binary.extend(self.public_key.as_bytes());

        if let Some(ref change) = self.change {
            binary.extend(change.0.to_be_bytes().as_ref());
            binary.extend(change.1.as_bytes())
        }

        format!(
            "PROPOSE!{}!{}!{}",
            self.oracle,
            self.event_id,
            base2048::encode(&binary[..])
        )
    }

    pub fn from_str(string: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut segments = string.split("!");
        if segments.next() != Some("PROPOSE") {
            return Err("not a proposal")?;
        }
        let oracle = segments.next().ok_or("missing oralce")?;
        let event_id = EventId::from_str(segments.next().ok_or("missing event id")?)?;
        let base2048_encoded = segments.next().ok_or("missing base2048 encoded data")?;
        let binary = base2048::decode(base2048_encoded).ok_or("invalid base2048 encoding")?;
        if binary.len() < 2 {
            return Err("too short")?;
        }

        match binary[0] {
            0x00 => {
                let (n_inputs, mut remaining) = binary[1..].split_first().ok_or("too short")?;
                let n_inputs = *n_inputs as usize;
                let mut inputs = Vec::with_capacity(n_inputs);
                for _ in 0..n_inputs {
                    let (vout, tail) = remaining.split_first().ok_or("too short")?;
                    let (txid, tail) = checked_split_at(tail, 32).ok_or("too short")?;
                    let txid = Txid::from_slice(&txid).unwrap();
                    inputs.push(OutPoint::new(txid, (*vout).into()));
                    remaining = tail
                }

                let (public_key, remaining) = checked_split_at(remaining, 32).ok_or("too short")?;
                let public_key = XOnly::from_slice(public_key).ok_or("invalid public key")?;
                let change = if remaining.len() > 0 {
                    let (value_slice, remaining) =
                        checked_split_at(remaining, 8).ok_or("too short")?;
                    let mut value = [0u8; 8];
                    value.copy_from_slice(&value_slice);
                    let value = u64::from_be_bytes(value);
                    let script = Script::from(remaining.to_vec());
                    Some((value, script))
                } else {
                    None
                };

                Ok(Proposal {
                    oracle: oracle.to_string(),
                    event_id,
                    inputs,
                    public_key,
                    change,
                })
            }
            _ => Err("Unknown type tag")?,
        }
    }
}

fn checked_split_at(slice: &[u8], mid: usize) -> Option<(&[u8], &[u8])> {
    if slice.len() < mid {
        return None;
    }
    Some(slice.split_at(mid))
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
        inputs,
        public_key: keypair.public_key,
        change: change_script.map(|script| (value, script)),
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
            inputs: vec![
                OutPoint::new(Txid::from_slice(&[1u8; 32]).unwrap(), 0),
                OutPoint::new(Txid::from_slice(&[2u8; 32]).unwrap(), 1),
            ],
            public_key: forty_two,
            change: None,
        };

        let encoded = proposal.to_string();
        let decoded = Proposal::from_str(&encoded).unwrap();
        assert_eq!(decoded, proposal);

        proposal.change = Some((100_000, change_address.script_pubkey()));

        let encoded = proposal.to_string();
        dbg!(&encoded);
        let decoded = Proposal::from_str(&encoded).unwrap();
        assert_eq!(decoded, proposal);
        panic!()
    }
}
