use super::CmdOutput;
use crate::elog;
use crate::{
    cmd,
    config::{Config, GunSigner},
    frost::FrostTranscript,
};
use anyhow::Context;
use std::{fs::File, path::Path};

pub fn run_sign_cmd(wallet_dir: &Path, config: &Config) -> anyhow::Result<CmdOutput> {
    for signer in &config.signers {
        match signer {
            GunSigner::SeedWordsFile { .. } => todo!(),
            GunSigner::PsbtDir { .. } => todo!(),
            GunSigner::Frost {
                joint_key,
                my_signer_index,
                working_dir,
            } => {
                let (secret_share, my_poly_secret) = cmd::load_frost_share(wallet_dir)?;

                let mut need_to_sign = std::fs::read_dir(working_dir)?
                    .filter_map(|path| Some(path.ok()?.path()))
                    .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("frost"))
                    .map(|file| {
                        let reader = File::open(&file).unwrap();
                        let frost_transcript: FrostTranscript =
                            serde_json::from_reader(reader).unwrap();

                        (frost_transcript, file)
                    })
                    .filter(|(transcript, file)| {
                        if transcript.missing_signatures().contains(&my_signer_index) {
                            true
                        }
                        else {
                            elog!(@warning "Ignoring {} because it doesn't require our signature.", file.strip_prefix(working_dir).unwrap().display());
                            false
                        }

                    }).collect::<Vec<_>>();

                for (transcript, file) in &mut need_to_sign {
                    elog!(@magic "Found transaction to sign {}", file.strip_prefix(working_dir).unwrap().display());
                    if cmd::read_yn(&format!(
                        "{}\nDo you want to sign the above trasaction?",
                        cmd::display_psbt(config.network, &transcript.psbt)
                    )) {

                        transcript.contribute(
                            &joint_key,
                            *my_signer_index,
                            &secret_share,
                            &my_poly_secret,
                        )?;


                        std::fs::write(&file, serde_json::to_string_pretty(&transcript).unwrap())
                            .with_context(|| {
                            format!("Writing FROST signing file '{}' failed", file.display())
                        })?;

                        let missing = transcript.missing_signatures();

                        elog!(@magic "Successfully signed {}", file.strip_prefix(working_dir).unwrap().display());
                        if missing.is_empty() {
                            elog!(@celebration "Signing is finished! (but you're still going to have to broadcast it the initiating wallet...)");
                        } else {
                            elog!(@info "You still need to get signers [{}] to contribute to finish the signature", missing.into_iter().map(|x| x.to_string()).collect::<Vec<_>>().join(", "));
                        }
                    }
                }

                if need_to_sign.is_empty() {
                    elog!(@info "There was nothing to sign in {}", working_dir.display());
                }
            }
        }
    }

    Ok(CmdOutput::None)
}
