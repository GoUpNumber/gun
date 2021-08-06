use bincode::Options;

pub fn serialize_base2048<S: serde::Serialize>(thing: &S) -> String {
    base2048::encode(&serialize(thing))
}

pub fn serialize<S: serde::Serialize>(thing: &S) -> Vec<u8> {
    // this might fail if the thing has a #[serde(flatten)] in it.
    bincode::options()
        .allow_trailing_bytes()
        .with_varint_encoding()
        .serialize(thing)
        .unwrap()
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
    bincode::options()
        .allow_trailing_bytes()
        .with_varint_encoding()
        .deserialize(bytes)
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn make_sure_extra_bytes_not_added() {
        let bytes = vec![42u8; 11];
        assert_eq!(serialize(&bytes).len(), 12);
        assert_eq!(serialize_base2048(&bytes).chars().count(), 9);
    }
}
