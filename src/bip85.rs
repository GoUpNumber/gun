use bdk::bitcoin::{
    hashes::{sha512, Hash, HashEngine, Hmac, HmacEngine},
    secp256k1::{Secp256k1, SignOnly},
    util::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey},
};

pub fn get_bip85_bytes<const L: usize>(
    xpriv: ExtendedPrivKey,
    index: u32,
    secp: &Secp256k1<SignOnly>,
) -> [u8; L] {
    let path = DerivationPath::from(vec![
        ChildNumber::Hardened { index: 83696968 },
        ChildNumber::Hardened { index: 128169 },
        ChildNumber::Hardened { index: L as u32 },
        ChildNumber::Hardened { index: index },
    ]);
    let bip85_key = xpriv.derive_priv(&secp, &path).unwrap();

    let mut engine = HmacEngine::<sha512::Hash>::new("bip-entropy-from-k".as_bytes());
    engine.input(&bip85_key.private_key.serialize_secret());
    let hash = Hmac::<sha512::Hash>::from_engine(engine).into_inner();
    hash[..L].try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use olivia_secp256k1::fun::hex;
    use std::str::FromStr;

    #[test]
    fn test_vector_32() {
        let secp = Secp256k1::signing_only();
        let xpriv = ExtendedPrivKey::from_str("xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb").expect("reading extended private key");
        let expected_hex =
            hex::decode("ea3ceb0b02ee8e587779c63f4b7b3a21e950a213f1ec53cab608d13e8796e6dc")
                .expect("reading in expected test bytes");
        assert_eq!(
            get_bip85_bytes::<32>(xpriv, 0, &secp).to_vec(),
            expected_hex
        );
    }

    #[test]
    fn test_vector_64() {
        let secp = Secp256k1::signing_only();
        let xpriv = ExtendedPrivKey::from_str("xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb").expect("reading extended private key");
        let expected_hex =
            hex::decode("492db4698cf3b73a5a24998aa3e9d7fa96275d85724a91e71aa2d645442f878555d078fd1f1f67e368976f04137b1f7a0d19232136ca50c44614af72b5582a5c")
                .expect("reading in expected test bytes");
        assert_eq!(
            get_bip85_bytes::<64>(xpriv, 0, &secp).to_vec(),
            expected_hex
        );
    }
}
