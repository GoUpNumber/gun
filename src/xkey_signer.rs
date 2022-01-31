use bdk::{
    bitcoin::{
        secp256k1::{self, All, Secp256k1},
        util::{
            bip32::{self, ChildNumber, DerivationPath, ExtendedPrivKey},
            psbt::PartiallySignedTransaction,
        },
        Network,
    },
    wallet::signer::{Signer, SignerError, SignerId},
};
use miniscript::bitcoin::{PrivateKey, PublicKey};

#[derive(Debug)]
pub struct XKeySigner {
    /// The derivation path
    pub path: bip32::DerivationPath,
    /// The extended key
    pub parent_xkey: ExtendedPrivKey,
}

impl Signer for XKeySigner {
    fn sign(
        &self,
        psbt: &mut PartiallySignedTransaction,
        input_index: Option<usize>,
        secp: &Secp256k1<All>,
    ) -> Result<(), SignerError> {
        let xkey = self.parent_xkey.derive_priv(secp, &self.path).unwrap();
        let signer_fingerprint = self.parent_xkey.fingerprint(secp);
        let input_index = input_index.unwrap();
        if input_index >= psbt.inputs.len() {
            return Err(SignerError::InputIndexOutOfRange);
        }

        if psbt.inputs[input_index].final_script_sig.is_some()
            || psbt.inputs[input_index].final_script_witness.is_some()
        {
            return Ok(());
        }

        let child_matches = psbt.inputs[input_index].bip32_derivation.iter().find(
            |(_, &(fingerprint, ref path))| {
                if fingerprint != signer_fingerprint {
                    return false;
                }
                if self.path.len() > path.len() {
                    return false;
                }
                for (i, child_n) in self.path.into_iter().enumerate() {
                    if path[i] != *child_n {
                        return false;
                    }
                }
                true
            },
        );

        let (public_key, full_path) = match child_matches {
            Some((pk, (_, full_path))) => (pk, full_path.clone()),
            None => return Ok(()),
        };

        let deriv_path = DerivationPath::from(
            full_path
                .into_iter()
                .cloned()
                .skip(self.path.len())
                .collect::<Vec<ChildNumber>>(),
        );
        let derived_key = xkey.derive_priv(secp, &deriv_path).unwrap();

        if &PublicKey::new(secp256k1::PublicKey::from_secret_key(
            secp,
            &derived_key.private_key,
        )) != public_key
        {
            Err(SignerError::InvalidKey)
        } else {
            PrivateKey::new(derived_key.private_key, Network::Bitcoin).sign(
                psbt,
                Some(input_index),
                secp,
            )
        }
    }

    fn sign_whole_tx(&self) -> bool {
        false
    }

    fn id(&self, secp: &Secp256k1<All>) -> SignerId {
        SignerId::from(self.parent_xkey.fingerprint(secp))
    }
}
