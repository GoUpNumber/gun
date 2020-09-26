use magical::Wallet;
use magical::bitcoin::secp256k1::PublicKey;
use magical::UTXO;


pub trait WalletExt {
    fn public_key_for_p2wpkh_utxo(&self, utxo: &UTXO) -> Result<Option<PublicKey>, magical::Error>;
}


impl WalletExt for Wallet {
    fn public_key_for_p2wpkh_utxo(&self, utxo: &UTXO) -> Result<Option<PublicKey>, magical::Error> {
        unimplemented!()
    }
}
