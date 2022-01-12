use bdk::{
    bitcoin::{
        secp256k1::{All, Secp256k1},
        util::psbt::PartiallySignedTransaction,
        Network,
    },
    wallet::signer::{Signer, SignerError, SignerId},
};
use core::str::FromStr;
use std::path::PathBuf;

use crate::cmd::{display_psbt, read_yn};

#[derive(Debug)]
pub struct SDCardSigner {
    psbt_output_dir: PathBuf,
    network: Network,
}

impl SDCardSigner {
    pub fn create(psbt_output_dir: PathBuf, network: Network) -> Self {
        SDCardSigner {
            psbt_output_dir,
            network,
        }
    }
}

impl Signer for SDCardSigner {
    fn sign(
        &self,
        psbt: &mut PartiallySignedTransaction,
        _input_index: Option<usize>,
        _secp: &Secp256k1<All>,
    ) -> Result<(), SignerError> {
        if !read_yn(&format!(
            "This is the transaction that will be saved for signing.\n{}Ok",
            display_psbt(self.network, &psbt)
        )) {
            return Err(SignerError::UserCanceled);
        }

        let txid = psbt.clone().extract_tx().txid();
        let mut psbt_file = PathBuf::from(self.psbt_output_dir.clone());
        if !self.psbt_output_dir.exists() {
            eprintln!(
                "psbt-output-dir '{}' does not exist.",
                self.psbt_output_dir.display()
            );
            return Err(SignerError::UserCanceled);
        }
        psbt_file.push(format!("{}.psbt", txid.to_string()));

        if let Err(e) = std::fs::write(psbt_file.clone(), psbt.to_string()) {
            eprintln!("Was unable to write PSBT {}: {}", psbt_file.display(), e);
            return Err(SignerError::UserCanceled);
        }

        if !psbt_file.clone().exists() {
            eprintln!("Failed to write PSBT to {}", psbt_file.display());
            return Err(SignerError::UserCanceled);
        }

        eprintln!("Wrote PSBT to {}", psbt_file.display());

        let mut signed_psbt_file = PathBuf::from(self.psbt_output_dir.clone());
        signed_psbt_file.push(format!("{}-signed.psbt", txid.to_string()));
        eprintln!(
            "Please sign the PSBT and save it to {}",
            signed_psbt_file.display()
        );
        eprintln!("Press enter once signed.");
        let mut input = String::new();
        let _ = std::io::stdin().read_line(&mut input);

        let contents = match std::fs::read_to_string(signed_psbt_file.clone()) {
            Ok(contents) => contents,
            Err(e) => {
                eprintln!(
                    "Failed to read PSBT file {}: {}",
                    signed_psbt_file.display(),
                    e
                );
                return Err(SignerError::UserCanceled);
            }
        };

        let psbt_result = PartiallySignedTransaction::from_str(&contents.trim());

        if let Err(e) = psbt_result {
            eprintln!("Failed to parse PSBT file {}", signed_psbt_file.display());
            eprintln!("{}", e);
            return Err(SignerError::UserCanceled);
        };
        *psbt = psbt_result.unwrap();
        Ok(())
    }

    fn id(&self, _secp: &Secp256k1<All>) -> SignerId {
        // Fingerprint/PubKey is not used in anything important that we need just yet
        SignerId::Dummy(3735928559)
    }

    fn sign_whole_tx(&self) -> bool {
        true
    }
}
