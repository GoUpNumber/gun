use bincode::Options;

pub fn serialize<S: serde::Serialize>(thing: &S) -> String {
    base2048::encode(&bincode::options().serialize(thing).unwrap())
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("invalid base2048 encoding")]
    Base2048,
    #[error("invalid data: {0}")]
    Bincode(bincode::Error)
}




pub fn deserialize<D: serde::de::DeserializeOwned>(string: &str) -> anyhow::Result<D> {
    let decoded = base2048::decode(string).ok_or(DecodeError::Base2048)?;
    bincode::options().deserialize(&decoded[..]).map_err(anyhow::Error::new)
}
