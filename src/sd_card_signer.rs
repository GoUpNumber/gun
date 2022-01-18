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
        let psbt_file = self
            .psbt_output_dir
            .as_path()
            .join(format!("{}.psbt", txid.to_string()));
        loop {
            if !self.psbt_output_dir.exists() {
                eprintln!(
                    "psbt-output-dir '{}' does not exist (maybe you need to insert your SD card?).\nPress enter to try again.",
                    self.psbt_output_dir.display()
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
            self.psbt_output_dir
                .as_path()
                .join(format!("{}-signed.psbt", txid))
                .to_path_buf(),
            self.psbt_output_dir
                .as_path()
                .join(format!("{}-part.psbt", txid))
                .to_path_buf(),
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
        let psbt_result = PartiallySignedTransaction::from_str(&contents.trim());

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
        SignerId::Dummy(3735928559)
    }

    fn sign_whole_tx(&self) -> bool {
        true
    }
}
