use bdk::bitcoin::secp256k1;
use olivia_secp256k1::ecdsa_fun;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct SignedInput {
    pub outpoint: bdk::bitcoin::OutPoint,
    pub witness: Witness,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum Witness {
    P2wpkh {
        key: secp256k1::PublicKey,
        // using ecdsa_fun::Signature here ebcause it serializes to 64 bytes rather than DER
        signature: ecdsa_fun::Signature,
    },
}

impl Witness {
    pub fn encode(&self) -> Vec<Vec<u8>> {
        match self {
            Witness::P2wpkh { key, signature } => {
                let mut sig_bytes = secp256k1::Signature::from_compact(&signature.to_bytes())
                    .unwrap()
                    .serialize_der()
                    .to_vec();
                sig_bytes.push(0x01);
                let pk_bytes = key.serialize().to_vec();
                vec![sig_bytes, pk_bytes]
            }
        }
    }

    pub fn decode_p2wpkh(mut w: Vec<Vec<u8>>) -> Option<Self> {
        let key_bytes = w.pop()?;
        let mut sig_bytes = w.pop()?;
        let _sighash = sig_bytes.pop()?;
        let signature = secp256k1::Signature::from_der(&sig_bytes).ok()?.into();
        let key = secp256k1::PublicKey::from_slice(&key_bytes).ok()?;
        Some(Witness::P2wpkh { key, signature })
    }
}
