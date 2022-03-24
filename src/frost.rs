use crate::{
    cmd,
    cmd::FrostSetup,
    database::{GunDatabase, RemoteNonces},
    ecdh_frost as ecdh,
    ecdh_frost::KeyPair,
    elog,
};
use anyhow::{anyhow, Context};
use bdk::signer::Signer;
use bitcoin::{
    hashes::Hash,
    schnorr::{SchnorrSig, XOnlyPublicKey},
    secp256k1::{All, Secp256k1},
    util::{psbt::PartiallySignedTransaction as Psbt, sighash, taproot::TapTweakHash},
    Network,
};
use chacha20::cipher::StreamCipher;
use core::str::FromStr;
use rand::{CryptoRng, RngCore};
use schnorr_fun::{
    frost::{PointPoly, ScalarPoly, SignSession, *},
    fun::{marker::*, Point, Scalar},
    musig::Nonce,
    nonce::Deterministic,
    Message, Schnorr,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    path::{Path, PathBuf},
};

use crate::cmd::CommonArgs;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedShare(Point<EvenY>, [u8; 32]);

impl EncryptedShare {
    pub fn new(
        pk: Point<EvenY>,
        rng: &mut (impl RngCore + CryptoRng),
        share: &Scalar<Secret, Zero>,
        aux: &[u8],
    ) -> Self {
        let randomness = KeyPair::random(rng);
        let (mut cipher, _) = ecdh::ecdh_with_aux(&randomness, &pk, aux);
        let mut data = share.to_bytes();
        cipher.apply_keystream(&mut data);
        EncryptedShare(randomness.public_key, data)
    }

    pub fn decrypt(mut self, kp: &KeyPair, aux: &[u8]) -> Scalar<Secret, Zero> {
        let (mut cipher, _) = ecdh::ecdh_with_aux(&kp, &self.0, aux);
        cipher.apply_keystream(&mut self.1);
        Scalar::from_bytes_mod_order(self.1)
    }
}

pub struct State1 {
    my_poly: ScalarPoly,
    my_signer_index: usize,
}

pub struct State2 {
    my_poly_secret: Scalar,
    my_signer_index: usize,
    my_share: Scalar<Secret, Zero>,
    dkg: Dkg,
    commitment_digest: [u8; 32],
    frost: Frost<Schnorr<Sha256, Deterministic<Sha256>>>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct Transcript {
    pub threshold: usize,
    pub network: Network,
    pub signers: Vec<PointPoly>,
    pub shares: Vec<Vec<(EncryptedShare, Vec<Nonce>)>>,
}

impl Transcript {
    pub fn new(threshold: usize, network: Network) -> Self {
        Self {
            threshold,
            signers: vec![],
            shares: vec![],
            network,
        }
    }

    pub fn commitment_digest(&self) -> [u8; 32] {
        let mut sha2 = Sha256::default();
        for poly in self.signers.iter() {
            for point in poly.points() {
                sha2.update(point.to_bytes())
            }
        }
        sha2.finalize().try_into().unwrap()
    }

    pub fn round2_started(&self) -> bool {
        self.shares.len() > 0
    }

    pub fn round2_ready(&self) -> bool {
        self.signers.len() >= self.threshold
    }

    pub fn n_signers(&self) -> usize {
        self.signers.len()
    }

    pub fn missing_shares(&self) -> Vec<usize> {
        // Number of shares should be one less than number of signers, (minus themselves)
        //
        self.shares
            .iter()
            .enumerate()
            .filter(|(_, v)| v.len() < self.n_signers() - 1)
            .map(|(i, _)| i)
            // .chain(self.shares.len() - 0..self.n_signers())
            .collect()
    }

    pub fn add_signer(&mut self, my_poly: ScalarPoly) -> State1 {
        self.signers.push(my_poly.to_point_poly());
        State1 {
            my_poly,
            my_signer_index: self.signers.len() - 1,
        }
    }

    pub fn start_round_two(
        &mut self,
        State1 {
            my_poly,
            my_signer_index,
        }: State1,
    ) -> anyhow::Result<State2> {
        let commitment_digest = self.commitment_digest();
        let frost = Frost::<Schnorr<Sha256, Deterministic<Sha256>>>::default();
        if self.signers[my_signer_index] != my_poly.to_point_poly() {
            return Err(anyhow!(
                "Our first round data does not match what we expect so we must abort"
            ));
        }
        let dkg = frost.collect_polys(self.signers.clone())?;
        let my_poly_secret = my_poly.first_coef().clone();
        let shares = frost.create_shares(&dkg, my_poly);

        let encrypted_shares = self
            .signers
            .iter()
            .enumerate()
            .filter(|(signer_index, _)| *signer_index != my_signer_index)
            .map(|(signer_index, poly)| {
                let shares = EncryptedShare::new(
                    poly.points()[0].into_point_with_even_y().0,
                    &mut rand::thread_rng(),
                    &shares[signer_index],
                    &commitment_digest,
                );

                let nonces = (0..50usize)
                    .map(|j| {
                        frost
                            .gen_nonce(
                                &dkg,
                                my_signer_index,
                                &my_poly_secret,
                                &[my_signer_index.to_be_bytes(), j.to_be_bytes()].concat(),
                            )
                            .public()
                    })
                    .collect();
                (shares, nonces)
            })
            .collect();

        while self.shares.len() <= my_signer_index {
            self.shares.push(vec![])
        }

        self.shares[my_signer_index] = encrypted_shares;

        Ok(State2 {
            my_poly_secret,
            my_signer_index: my_signer_index,
            my_share: shares[my_signer_index].clone(),
            dkg,
            commitment_digest,
            frost,
        })
    }

    pub fn finish_round_two(
        self,
        State2 {
            my_poly_secret,
            my_signer_index,
            my_share,
            dkg,
            commitment_digest,
            frost,
        }: State2,
    ) -> anyhow::Result<KeyGenOutput> {
        if commitment_digest != self.commitment_digest() {
            return Err(anyhow!("transcript has been maliciously modified"));
        }

        let missing_shares = self.missing_shares();

        if !missing_shares.is_empty() {
            return Err(anyhow!("transcript is missing shares"));
        }

        let keypair = KeyPair::from_secret_key(my_poly_secret.clone());

        let (shares, nonces) = self
            .shares
            .iter()
            .enumerate()
            .map(|(i, encrypted_shares)| {
                if i == my_signer_index {
                    return (
                        my_share.clone(),
                        (0..50usize)
                            .map(|j| {
                                frost
                                    .gen_nonce(
                                        &dkg,
                                        my_signer_index,
                                        &my_poly_secret,
                                        &[my_signer_index.to_be_bytes(), j.to_be_bytes()].concat(),
                                    )
                                    .public()
                            })
                            .collect(),
                    );
                }
                let offset = (my_signer_index > i) as usize;
                let (encrypted_share, nonces) = encrypted_shares[my_signer_index - offset].clone();
                let decrypted_share = encrypted_share.decrypt(&keypair, &commitment_digest);
                (decrypted_share, nonces)
            })
            .unzip();

        let (secret_share, joint_key) = frost.collect_shares(dkg, my_signer_index, shares)?;

        Ok(KeyGenOutput {
            secret_share,
            joint_key,
            my_poly_secret,
            nonces,
            my_signer_index,
            network: self.network,
        })
    }
}

pub struct KeyGenOutput {
    pub secret_share: Scalar,
    pub joint_key: JointKey,
    pub my_poly_secret: Scalar,
    pub nonces: Vec<Vec<Nonce>>,
    pub my_signer_index: usize,
    pub network: Network,
}

fn read_transcript<T: serde::de::DeserializeOwned>(
    path: &Path,
    validate: impl Fn(&T) -> bool,
) -> T {
    loop {
        match File::open(path) {
            Ok(file) => match serde_json::from_reader::<_, T>(file) {
                Ok(transcript) => {
                    if validate(&transcript) {
                        break transcript;
                    }
                }
                Err(e) => elog!(@user_error "'{}' was not valid json: {}", path.display(), e),
            },
            Err(e) => elog!(@user_error "Could not open '{}' for reading: {}", path.display(), e),
        }

        elog!(@info "Press enter when you're ready to try again..");
        let _ = std::io::stdin().read_line(&mut String::new());
    }
}

pub fn run_frost_setup(setup_file: &Path, frost_setup: FrostSetup) -> anyhow::Result<KeyGenOutput> {
    match frost_setup {
        FrostSetup::Start {
            working_dir,
            threshold,
            common_args: CommonArgs { network },
        } => {
            if !working_dir.exists() {
                return Err(anyhow!(
                    "working directory {} doesn't exist",
                    working_dir.display()
                ));
            }

            let mut transcript = Transcript::new(threshold, network);
            let my_poly = ScalarPoly::random(threshold, &mut rand::thread_rng());

            let state = transcript.add_signer(my_poly);
            elog!(@info "Starting setup round 1: Adding devices");
            elog!(@suggestion "Communicate {} to the next device and run `gun setup forst add <path-to-directory-containing-frost-setup.json>`", setup_file.display());
            elog!(@suggestion "Load {} back on this device and press enter when ready", setup_file.display());
            let mut transcript = read_transcript(setup_file, |transcript: &Transcript| {
                if transcript.n_signers() < threshold {
                    if !transcript.round2_started() {
                        cmd::read_yn(&format!("You've added {} signing devices so far are you sure you don't want to add any more?", transcript.n_signers()))
                    } else {
                        true
                    }
                } else {
                    elog!(@user_error "You've only added {} signers so far but you need to add at least {}", transcript.n_signers(), threshold);
                    false
                }
            });

            let state = transcript.start_round_two(state)?;
            std::fs::write(
                setup_file,
                serde_json::to_string_pretty(&transcript).unwrap(),
            )
            .with_context(|| {
                format!("Writing FROST setup file '{}' failed", setup_file.display())
            })?;

            elog!(@info "Starting setup round 2: Generate secret shares");
            elog!(@suggestion "Communicate the updated {} to the next device", setup_file.display());
            elog!(@suggestion "Load {} back on this device and press enter when ready", setup_file.display());
            let transcript = read_transcript(setup_file, |transcript: &Transcript| {
                let missing_shares = transcript.missing_shares();
                if missing_shares.is_empty() {
                    true
                } else {
                    elog!(@user_error "'{}' is missing shares for devices at indexes {}", setup_file.display(), missing_shares.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "));
                    false
                }
            });
            let keygen_output = transcript.finish_round_two(state)?;
            Ok(keygen_output)
        }
        FrostSetup::Add { working_dir } => {
            if !working_dir.exists() {
                return Err(anyhow!(
                    "working directory {} doesn't exist",
                    working_dir.display()
                ));
            }
            let mut transcript = read_transcript(setup_file, |_: &Transcript| true);
            let my_poly = ScalarPoly::random(transcript.threshold, &mut rand::thread_rng());

            let state = transcript.add_signer(my_poly);
            elog!(@celebration "Device successfully registered");
            let state = if transcript.round2_ready()
                && !cmd::read_yn("Would you like to add more devices?")
            {
                transcript.start_round_two(state)?
            } else {
                let mut transcript = read_transcript(setup_file, |transcript: &Transcript| {
                    if transcript.n_signers() < transcript.threshold {
                        if !transcript.round2_started() {
                            cmd::read_yn(&format!("You've added {} signing devices so far are you sure you don't want to add any more?", transcript.n_signers()))
                        } else {
                            true
                        }
                    } else {
                        elog!(@user_error "You've only added {} signers so far but you need to add at least {}", transcript.n_signers(), transcript.threshold);
                        false
                    }
                });
                transcript.start_round_two(state)?
            };

            elog!(@info "Starting setup round 2: Generate secret shares");
            elog!(@suggestion "Communicate the updated {} to the next device", setup_file.display());
            elog!(@suggestion "Load {} back on this device and press enter when ready", setup_file.display());
            let mut transcript = read_transcript(setup_file, |transcript: &Transcript| {
                let missing_shares = transcript.missing_shares();
                if missing_shares.is_empty() {
                    true
                } else {
                    elog!(@user_error "'{}' is missing shares for devices at indexes {}", setup_file.display(), missing_shares.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "));
                    false
                }
            });
            let keygen_output = transcript.finish_round_two(state)?;
            Ok(keygen_output)
        }
    }
}

#[derive(Debug, Clone)]
pub struct FrostSigner {
    pub joint_key: JointKey,
    pub my_signer_index: usize,
    pub secret_share: Scalar,
    pub my_poly_secret: Scalar,
    pub working_dir: PathBuf,
    pub db: GunDatabase,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NonceSpec {
    pub nonce_hint: usize,
    pub signer_nonce: Nonce,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FrostInputPartyShare {
    pub nonce_spec: NonceSpec,
    pub signature_shares: Vec<(usize, Scalar<Public, Zero>)>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FrostTranscript {
    pub psbt: Psbt,
    pub initiator_index: usize,
    pub signer_set: BTreeMap<usize, BTreeMap<usize, NonceSpec>>,
    pub signature_shares: BTreeMap<usize, BTreeMap<usize, Scalar<Public, Zero>>>,
}

impl FrostTranscript {
    pub fn missing_signatures(&self) -> BTreeSet<usize> {
        self.signature_shares
            .iter()
            .map(|(_, tr)| {
                tr.iter()
                    .filter(|(_, (_, sig_share))| sig_share.is_none())
                    .map(|(signer_index, _)| *signer_index)
            })
            .flatten()
            .collect()
    }

    pub fn new(
        initiator_index: usize,
        psbt: Psbt,
        joint_key: &JointKey,
        signer_set: BTreeMap<usize, BTreeMap<usize, NonceSpec>>,
    ) -> Self {
        Ok(FrostTranscript {
            psbt,
            initiator_index,
            signer_set,
            signature_shares: BTreeMap::new(),
        })
    }

    fn get_frost_session(
        &self,
        frost: &Frost<Schnorr<Sha256, Deterministic<Sha256>>, Sha256>,
        joint_key: &JointKey,
        input_index: usize,
    ) -> anyhow::Result<SignSession> {
        let input = self
            .signature_shares
            .get(&input_index)
            .expect("should exist");
        let tx_digest = message_from_psbt(&self.psbt, input_index)?;
        let message = Message::<Public>::raw(&tx_digest);
        let public_nonces = input
            .iter()
            .map(|(signer_index, (nonce_spec, _))| (*signer_index, nonce_spec.signer_nonce))
            .collect::<Vec<_>>();
        Ok(frost.start_sign_session(joint_key, &public_nonces, message))
    }

    fn get_tweaked_key(joint_key: &JointKey) -> JointKey {
        let tweak = Scalar::from_bytes_mod_order(
            TapTweakHash::from_key_and_tweak(joint_key.public_key().into(), None).into_inner(),
        );
        joint_key.clone().tweak(tweak).unwrap()
    }

    pub fn contribute(
        &mut self,
        joint_key: &JointKey,
        my_signer_index: usize,
        initiator_index: usize,
        secret_share: &Scalar,
        my_poly_secret: &Scalar,
    ) -> anyhow::Result<()> {
        let frost = Frost::<Schnorr<Sha256, Deterministic<Sha256>>, Sha256>::default();
        let joint_key = Self::get_tweaked_key(joint_key);
        let sessions = self
            .signature_shares
            .iter()
            .map(|(input_index, _)| self.get_frost_session(&frost, &joint_key, *input_index))
            .collect::<Result<Vec<_>, _>>()?;

        for ((_, input), session) in self.signature_shares.iter_mut().zip(sessions) {
            let (nonce_spec, sig_share) = input
                .get_mut(&my_signer_index)
                .ok_or(anyhow!("you're not signing for this one!"))?;
            let nonce_keypair = frost.gen_nonce(
                &joint_key,
                my_signer_index,
                my_poly_secret,
                &[
                    initiator_index.to_be_bytes(),
                    nonce_spec.nonce_hint.to_be_bytes(),
                ]
                .concat(),
            );

            if nonce_keypair.public() != nonce_spec.signer_nonce {
                return Err(anyhow!("Nonce didn't match initiator's nonce"));
            }

            *sig_share = Some(frost.sign(
                &joint_key,
                &session,
                my_signer_index,
                secret_share,
                nonce_keypair,
            ));
        }

        Ok(())
    }

    pub fn finish(mut self, joint_key: &JointKey) -> anyhow::Result<Psbt> {
        let frost = Frost::<Schnorr<Sha256, Deterministic<Sha256>>, Sha256>::default();
        let joint_key = Self::get_tweaked_key(joint_key);

        for (input_index, input) in self.signature_shares.iter() {
            let session = self.get_frost_session(&frost, &joint_key, *input_index)?;

            let sig_shares = input
                .iter()
                .map(|(signer_index, (_, sig))| {
                    let sig =
                        sig.ok_or(anyhow!("Missing signature share from {}", signer_index))?;
                    if !frost.verify_signature_share(&joint_key, &session, *signer_index, sig) {
                        return Err(anyhow!(
                            "The signature share from signer {} was invalid",
                            signer_index
                        ));
                    }

                    Ok(sig)
                })
                .collect::<Result<Vec<_>, _>>()?;

            let signature = frost.combine_signature_shares(&joint_key, &session, sig_shares);
            self.psbt.inputs[*input_index].tap_key_sig = Some(SchnorrSig {
                sig: signature.into(),
                hash_ty: sighash::SchnorrSigHashType::Default,
            });
        }

        Ok(self.psbt)
    }
}

use bdk::wallet::signer::SignerError;
pub fn message_from_psbt(psbt: &Psbt, input_index: usize) -> Result<[u8; 32], SignerError> {
    let mut cache = sighash::SigHashCache::new(&psbt.unsigned_tx);

    let witness_utxos = psbt
        .inputs
        .iter()
        .map(|i| i.witness_utxo.clone())
        .collect::<Option<Vec<_>>>()
        .ok_or(SignerError::MissingWitnessUtxo)?;

    let psbt_input = &psbt.inputs[input_index];

    let prevouts = sighash::Prevouts::All(&witness_utxos);
    let sighash_type = psbt_input
        .sighash_type
        .map(sighash::SchnorrSigHashType::from)
        .unwrap_or(sighash::SchnorrSigHashType::Default);

    let sighash = cache
        .taproot_signature_hash(input_index, &prevouts, None, None, sighash_type)
        .unwrap();

    Ok(sighash.into_inner())
}

// TODO:
//
// 1. Write a FrostSignTranscript for each input. Probably just a newtype vec of FrostSignTranscript.
// 2. Add cmd gun frost-sign which reads a FrostSignTranscripts from a file and adds secret shares.
// 3. Actually add nonces to the keygen stage (but this can be done last).

impl FrostSigner {
    fn _sign(&self, psbt: &mut Psbt) -> anyhow::Result<()> {
        elog!(@question "Which other signers are going to sign? Specify {} indexes seperated by spaces", self.joint_key.threshold() - 1);
        let coalition = loop {
            let mut signers = String::new();
            std::io::stdin().read_line(&mut signers)?;
            let signers = signers
                .split(' ')
                .map(|signer| usize::from_str(signer))
                .collect::<Result<BTreeSet<_>, _>>();
            if let Ok(signers) = signers {
                if signers
                    .iter()
                    .all(|signer| *signer < self.joint_key.n_signers())
                    && signers.len() == self.joint_key.threshold()
                {
                    break signers;
                } else {
                    elog!(@user_error "Invalid signer list try again");
                }
            } else {
                elog!(@user_error "Invalid signer list try again");
            }
        };

        let signers = self.db.fetch_and_increment_nonces(coalition);

        let mut frost_transcript =
            FrostTranscript::new(self.my_signer_index, psbt.clone(), &self.joint_key, signers)?;
        frost_transcript.contribute(
            &self.joint_key,
            self.my_signer_index,
            self.my_signer_index,
            &self.secret_share,
            &self.my_poly_secret,
        )?;

        let txid = psbt.clone().extract_tx().txid();
        let frost_transcript_file = self.working_dir.join(format!("{}.frost", txid));

        while let Err(e) = std::fs::write(
            &frost_transcript_file,
            serde_json::to_string(&frost_transcript).unwrap(),
        ) {
            elog!(@user_error "Failed to write frost signing session to {}: {}", frost_transcript_file.display(), e);
            elog!(@suggestion "Press enter to try again.");
            let _ = std::io::stdin().read_line(&mut String::new());
        }

        elog!(@info "Frost signing session successfully written to {}", frost_transcript_file.display());
        elog!(@suggestion "Pass session to each other signing device and press enter when you have returned it.");

        let frost_transcript = read_transcript(
            frost_transcript_file.as_path(),
            |transcript: &FrostTranscript| {
                let missing_signers = transcript.missing_signatures();
                if missing_signers.is_empty() {
                    true
                } else {
                    elog!(@user_error "'{}' is missing shares for devices at indexes {}", frost_transcript_file.display(), missing_signers.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "));
                    false
                }
            },
        );

        *psbt = frost_transcript.finish(&self.joint_key)?;

        Ok(())
    }
}

impl Signer for FrostSigner {
    fn sign(
        &self,
        psbt: &mut Psbt,
        _input_index: Option<usize>,
        _secp: &Secp256k1<All>,
    ) -> Result<(), bdk::signer::SignerError> {
        if let Err(e) = self._sign(psbt) {
            elog!(@user_error "{}", e);
            return Err(bdk::signer::SignerError::UserCanceled);
        }
        Ok(())
    }

    fn sign_whole_tx(&self) -> bool {
        true
    }

    fn id(&self, _secp: &Secp256k1<All>) -> bdk::signer::SignerId {
        bdk::signer::SignerId::XOnly(self.joint_key.public_key().to_xonly().into())
    }
}

impl GunDatabase {
    pub fn fetch_and_increment_nonces(
        &self,
        signers: BTreeSet<usize>,
    ) -> BTreeMap<usize, NonceSpec> {
        unimplemented!()
    }
}
