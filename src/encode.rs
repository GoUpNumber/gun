use bincode::Options;

pub fn serialize_base2048<S: serde::Serialize>(thing: &S) -> String {
    base2048::encode(&serialize(thing))
}

pub fn serialize<S: serde::Serialize>(thing: &S) -> Vec<u8> {
    bincode::options().serialize(thing).unwrap()
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("invalid base2048 encoding")]
    Base2048,
    #[error("invalid data: {0}")]
    Bincode(bincode::Error),
}

pub fn deserialize_base2048<D: serde::de::DeserializeOwned>(
    string: &str,
) -> Result<D, DecodeError> {
    let decoded = base2048::decode(string).ok_or(DecodeError::Base2048)?;
    deserialize(&decoded[..]).map_err(DecodeError::Bincode)
}

pub fn deserialize<D: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<D, bincode::Error> {
    bincode::options().deserialize(bytes)
}
