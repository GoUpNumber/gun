use std::{path::PathBuf, str::FromStr};

use bdk::{
    bitcoin::{
        secp256k1::{self, All, Secp256k1},
        util::{
            bip32::{ExtendedPrivKey, Fingerprint},
            psbt::PartiallySignedTransaction,
        },
        Network,
    },
    keys::{bip39::Mnemonic, DerivableKey, ExtendedKey},
    wallet::signer::{Signer, SignerError, SignerId},
};
use miniscript::bitcoin::{PrivateKey, PublicKey};

use crate::cmd::{display_psbt, read_yn};

#[derive(Debug)]
pub struct XKeySigner {
    /// The extended key
    pub master_xkey: ExtendedPrivKey,
}

impl Signer for XKeySigner {
    fn sign(
        &self,
        psbt: &mut PartiallySignedTransaction,
        input_index: Option<usize>,
        secp: &Secp256k1<All>,
    ) -> Result<(), SignerError> {
        let signer_fingerprint = self.master_xkey.fingerprint(secp);
        let input_index = input_index.unwrap();
        if input_index >= psbt.inputs.len() {
            return Err(SignerError::InputIndexOutOfRange);
        }

        if psbt.inputs[input_index].final_script_sig.is_some()
            || psbt.inputs[input_index].final_script_witness.is_some()
        {
            return Ok(());
        }

        let child_matches = psbt.inputs[input_index]
            .bip32_derivation
            .iter()
            .find(|(_, &(fingerprint, _))| fingerprint == signer_fingerprint);

        let (public_key, full_path) = match child_matches {
            Some((pk, (_, full_path))) => (pk, full_path.clone()),
            None => return Ok(()),
        };

        let derived_key = self.master_xkey.derive_priv(secp, &full_path).unwrap();

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
        true
    }

    fn id(&self, secp: &Secp256k1<All>) -> SignerId {
        SignerId::from(self.master_xkey.fingerprint(secp))
    }
}

#[derive(Debug)]
pub struct PwSeedSigner {
    /// Seed Mnemonic (without passphrase)
    pub mnemonic: Mnemonic,
    /// Bitcoin network
    pub network: Network,
    /// The expected external wallet descriptor
    pub master_fingerprint: Fingerprint,
}

pub const PSBT_SIGNER_ID: u64 = 3735928559;

impl Signer for PwSeedSigner {
    fn sign(
        &self,
        psbt: &mut PartiallySignedTransaction,
        input_index: Option<usize>,
        secp: &Secp256k1<All>,
    ) -> Result<(), SignerError> {
        let master_xkey = loop {
            let p = rpassword::prompt_password_stderr("Please enter your wallet passphrase: ");
            let passphrase = match p {
                Ok(passphrase) => passphrase,
                Err(e) => {
                    eprintln!("Failed to read in password: {}", e);
                    return Err(SignerError::InvalidKey);
                }
            };
            let full_seed = self.mnemonic.to_seed(passphrase);
            let xkey: ExtendedKey = full_seed.into_extended_key().unwrap();
            let master_xkey = xkey.into_xprv(self.network).unwrap();

            if master_xkey.fingerprint(secp) != self.master_fingerprint {
                eprintln!("Invalid passphrase, derived fingerprint does not match. Try again.\n");
            } else {
                break master_xkey;
            }
        };

        let signer = XKeySigner { master_xkey };
        signer.sign(psbt, input_index, secp)
    }

    fn sign_whole_tx(&self) -> bool {
        false
    }

    fn id(&self, _secp: &Secp256k1<All>) -> SignerId {
        SignerId::from(self.master_fingerprint)
    }
}

#[derive(Debug)]
pub struct PsbtDirSigner {
    path: PathBuf,
    network: Network,
}

impl PsbtDirSigner {
    pub fn create(psbt_signer_dir: PathBuf, network: Network) -> Self {
        PsbtDirSigner {
            path: psbt_signer_dir,
            network,
        }
    }
}

impl Signer for PsbtDirSigner {
    fn sign(
        &self,
        psbt: &mut PartiallySignedTransaction,
        _input_index: Option<usize>,
        _secp: &Secp256k1<All>,
    ) -> Result<(), SignerError> {
        if !read_yn(&format!(
            "This is the transaction that will be saved for signing.\n{}Ok",
            display_psbt(self.network, psbt)
        )) {
            return Err(SignerError::UserCanceled);
        }

        let txid = psbt.clone().extract_tx().txid();
        let psbt_file = self.path.as_path().join(format!("{}.psbt", txid));
        loop {
            if !self.path.exists() {
                eprintln!(
                    "PSBT directory '{}' does not exist (maybe you need to insert your SD card?).\nPress enter to try again.",
                    self.path.display()
                );
                let _ = std::io::stdin().read_line(&mut String::new());
            } else if let Err(e) = std::fs::write(&psbt_file, psbt.to_string()) {
                eprintln!(
                    "Was unable to write PSBT {}: {}\nPress enter to try again.",
                    psbt_file.display(),
                    e
                );
                let _ = std::io::stdin().read_line(&mut String::new());
            } else {
                break;
            }
        }

        eprintln!("Wrote PSBT to {}", psbt_file.display());

        let file_locations = [
            self.path.as_path().join(format!("{}-signed.psbt", txid)),
            self.path.as_path().join(format!("{}-part.psbt", txid)),
        ];
        eprintln!("gun will look for the signed psbt files at:",);
        for location in &file_locations {
            eprintln!("- {}", location.display());
        }
        eprintln!("Press enter once signed.");
        let (signed_psbt_path, contents) = loop {
            let _ = std::io::stdin().read_line(&mut String::new());
            let mut file_contents = file_locations
                .iter()
                .map(|location| (location.clone(), std::fs::read_to_string(&location)))
                .collect::<Vec<_>>();
            match file_contents
                .iter()
                .find(|(_, file_content)| file_content.is_ok())
            {
                Some((signed_psbt_path, contents)) => {
                    break (signed_psbt_path.clone(), contents.as_ref().unwrap().clone())
                }
                None => eprintln!(
                    "Couldn't read any of the files: {}\nPress enter to try again.",
                    file_contents.remove(0).1.unwrap_err()
                ),
            }
        };
        let psbt_result = PartiallySignedTransaction::from_str(contents.trim());

        match psbt_result {
            Err(e) => {
                eprintln!("Failed to parse PSBT file {}", signed_psbt_path.display());
                eprintln!("{}", e);
                Err(SignerError::UserCanceled)
            }
            Ok(read_psbt) => {
                let _ = std::fs::remove_file(psbt_file);
                let _ = std::fs::remove_file(signed_psbt_path);
                *psbt = read_psbt;
                Ok(())
            }
        }
    }

    fn id(&self, _secp: &Secp256k1<All>) -> SignerId {
        // Fingerprint/PubKey is not used in anything important that we need just yet
        SignerId::Dummy(PSBT_SIGNER_ID)
    }

    fn sign_whole_tx(&self) -> bool {
        true
    }
}
