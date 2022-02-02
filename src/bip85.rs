use bdk::bitcoin::{
    hashes::{sha512, Hash, HashEngine, Hmac, HmacEngine},
    secp256k1::Secp256k1,
    util::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey},
};

pub fn get_bip85_bytes<const L: usize>(
    xpriv: ExtendedPrivKey,
    app_num: u32,
    index: u32,
) -> [u8; L] {
    let path = DerivationPath::from(vec![
        ChildNumber::Hardened { index: 83696968 },
        ChildNumber::Hardened { index: app_num },
        ChildNumber::Hardened { index: index },
    ]);
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
        let expected_hex =
            hex::decode("efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7")
                .expect("reading in expected test bytes");
        assert_eq!(get_bip85_bytes::<64>(xpriv, 0, 0).to_vec(), expected_hex);
    }

    #[test]
    fn test_vector_2() {
        let xpriv = ExtendedPrivKey::from_str("xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb").expect("reading extended private key");
        let expected_hex =
            hex::decode("70c6e3e8ebee8dc4c0dbba66076819bb8c09672527c4277ca8729532ad711872218f826919f6b67218adde99018a6df9095ab2b58d803b5b93ec9802085a690e")
                .expect("reading in expected test bytes");
        assert_eq!(get_bip85_bytes::<64>(xpriv, 0, 1).to_vec(), expected_hex);
    }
}
