use bdk::bitcoin::{
    hashes::{sha512, Hash, HashEngine, Hmac, HmacEngine},
    secp256k1::Secp256k1,
    util::bip32::{DerivationPath, ExtendedPrivKey},
};

pub fn get_bip85_bytes<const L: usize>(xpriv: ExtendedPrivKey, path: DerivationPath) -> [u8; L] {
    let secp = Secp256k1::signing_only();
    let bip85_key = xpriv.derive_priv(&secp, &path).unwrap();

    let mut engine = HmacEngine::<sha512::Hash>::new("bip-entropy-from-k".as_bytes());
    engine.input(&bip85_key.private_key.serialize_secret());
    let hash = Hmac::<sha512::Hash>::from_engine(engine).into_inner();
    hash[(64 - L)..].try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use olivia_secp256k1::fun::hex;
    use std::str::FromStr;

    #[test]
    fn test_vector_1() {
        let xpriv = ExtendedPrivKey::from_str("xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb").expect("reading extended private key");
        let path = DerivationPath::from_str("m/83696968'/0'/0'").expect("reading derivation path");
        let expected_hex =
            hex::decode("efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7")
                .expect("reading in expected test bytes");
        assert_eq!(get_bip85_bytes::<64>(xpriv, path).to_vec(), expected_hex);
    }

    #[test]
    fn test_vector_2() {
        let xpriv = ExtendedPrivKey::from_str("xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb").expect("reading extended private key");
        let path = DerivationPath::from_str("m/83696968'/0'/1'").expect("reading derivation path");
        let expected_hex =
            hex::decode("70c6e3e8ebee8dc4c0dbba66076819bb8c09672527c4277ca8729532ad711872218f826919f6b67218adde99018a6df9095ab2b58d803b5b93ec9802085a690e")
                .expect("reading in expected test bytes");
        assert_eq!(get_bip85_bytes::<64>(xpriv, path).to_vec(), expected_hex);
    }

    #[test]
    fn test_vector_32() {
        let xpriv = ExtendedPrivKey::from_str("xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb").expect("reading extended private key");
        let path = DerivationPath::from_str("m/83696968'/32'/0'").expect("reading derivation path");
        let expected_hex =
            hex::decode("ead0b33988a616cf6a497f1c169d9e92562604e38305ccd3fc96f2252c177682")
                .expect("reading in expected test bytes");
        assert_eq!(get_bip85_bytes::<32>(xpriv, path).to_vec(), expected_hex);
    }

    #[test]
    fn test_vector_128169() {
        let xpriv = ExtendedPrivKey::from_str("xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb").expect("reading extended private key");
        let path = DerivationPath::from_str("m/83696968'/128169'/64'/0'")
            .expect("reading derivation path");
        let expected_hex =
            hex::decode("492db4698cf3b73a5a24998aa3e9d7fa96275d85724a91e71aa2d645442f878555d078fd1f1f67e368976f04137b1f7a0d19232136ca50c44614af72b5582a5c")
                .expect("reading in expected test bytes");
        assert_eq!(get_bip85_bytes::<64>(xpriv, path).to_vec(), expected_hex);
    }
}
