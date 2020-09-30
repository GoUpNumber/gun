use bdk::bitcoin::Script;

#[derive(Debug, Clone, PartialEq)]
struct BinScript(Script);

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
    value: u64,
    script_pubkey: BinScript,
}

impl Change {
    pub fn new(value: u64, script_pubkey: Script) -> Self {
        Change {
            value,
            script_pubkey: script_pubkey.into(),
        }
    }

    pub fn value(&self) -> u64 {
        self.value
    }

    pub fn script(&self) -> &Script {
        &self.script_pubkey.0
    }
}

impl<'de> serde::Deserialize<'de> for BinScript {
    fn deserialize<D: serde::de::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<BinScript, D::Error> {
        Ok(BinScript(Script::from(Vec::<u8>::deserialize(
            deserializer,
        )?)))
    }
}

impl<'de> serde::Serialize for BinScript {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0.to_bytes()[..])
    }
}
