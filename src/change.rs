use bdk::bitcoin::{Amount, Script};
use olivia_secp256k1::fun::hex;

#[derive(Debug, Clone, PartialEq)]
pub struct BinScript(Script);

impl From<BinScript> for Script {
    fn from(binscript: BinScript) -> Script {
        binscript.0
    }
}

impl From<Script> for BinScript {
    fn from(script: Script) -> Self {
        BinScript(script)
    }
}

impl From<Vec<u8>> for BinScript {
    fn from(bytes: Vec<u8>) -> Self {
        BinScript(Script::from(bytes))
    }
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct Change {
    #[serde(with = "bdk::bitcoin::util::amount::serde::as_sat")]
    value: Amount,
    script_pubkey: BinScript,
}

impl Change {
    pub fn new(value: u64, script_pubkey: Script) -> Self {
        Change {
            value: Amount::from_sat(value),
            script_pubkey: script_pubkey.into(),
        }
    }

    pub fn value(&self) -> Amount {
        self.value
    }

    pub fn script(&self) -> &Script {
        &self.script_pubkey.0
    }

    pub fn binscript(&self) -> &BinScript {
        &self.script_pubkey
    }
}
use serde::de::Error;

impl<'de> serde::Deserialize<'de> for BinScript {
    fn deserialize<D: serde::de::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<BinScript, D::Error> {
        if deserializer.is_human_readable() {
            Ok(BinScript(Script::from(
                hex::decode(&String::deserialize(deserializer)?)
                    .map_err(|e| D::Error::custom(format!("{}", e)))?,
            )))
        } else {
            Ok(BinScript(Script::from(Vec::<u8>::deserialize(
                deserializer,
            )?)))
        }
    }
}

impl<'de> serde::Serialize for BinScript {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(&self.0.as_bytes()))
        } else {
            serializer.serialize_bytes(self.0.as_bytes())
        }
    }
}
