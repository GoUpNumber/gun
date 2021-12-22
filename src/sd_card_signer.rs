use anyhow::Context;
use bdk::{
    bitcoin::{
        secp256k1::{All, Secp256k1},
        util::psbt::PartiallySignedTransaction,
    },
    wallet::signer::{Signer, SignerError, SignerId},
};
use core::str::FromStr;
use std::path::PathBuf;

#[derive(Debug)]
pub struct SDCardSigner {
    psbt_output_dir: PathBuf,
}

impl SDCardSigner {
    pub fn create(psbt_output_dir: PathBuf) -> Self {
        SDCardSigner { psbt_output_dir }
    }
}

impl Signer for SDCardSigner {
    fn sign(
        &self,
        psbt: &mut PartiallySignedTransaction,
        _input_index: Option<usize>,
        _secp: &Secp256k1<All>,
    ) -> Result<(), SignerError> {
        // Probably should figure out how to incorporate SignerErrors here
        let txid = psbt.clone().extract_tx().txid();
        let mut psbt_file = PathBuf::from(self.psbt_output_dir.clone());
        psbt_file.push(format!("{}.psbt", txid.to_string()));

        let _ = std::fs::write(psbt_file.clone(), psbt.to_string())
            .context("writing PSBT file to SD path");

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

        let contents = std::fs::read_to_string(signed_psbt_file.clone())
            .with_context(|| format!("Reading PSBT file {}", signed_psbt_file.display()));
        let psbt_result = PartiallySignedTransaction::from_str(&contents.unwrap().trim());

        if let Err(e) = psbt_result {
            eprintln!(
                "Failed to read signed PSBT file {}",
                signed_psbt_file.display()
            );
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
