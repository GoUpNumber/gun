use crate::{
    cmd, cmd::FrostSetup, database::GunDatabase, ecdh_frost as ecdh, ecdh_frost::KeyPair, elog,
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
    musig::{Nonce, NonceKeyPair},
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
const N_NONCES: usize = 50;

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

                let nonces = (0..N_NONCES)
                    .map(|j| {
                        frost
                            .gen_nonce(
                                &dkg,
                                my_signer_index,
                                &my_poly_secret,
                                &[signer_index.to_be_bytes(), j.to_be_bytes()].concat(),
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
                        (0..N_NONCES)
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
    mut dont_wait_first: bool,
    validate: impl Fn(&T) -> bool,
) -> T {
    loop {
        if dont_wait_first {
            dont_wait_first = false;
        } else {
            let _ = std::io::stdin().read_line(&mut String::new());
        }
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

        elog!(@suggestion "Press enter to try again...");
    }
}

pub fn run_frost_setup(setup_file: &Path, frost_setup: FrostSetup) -> anyhow::Result<KeyGenOutput> {
    let (setup_file, mut transcript, state) = match frost_setup {
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
            std::fs::write(
                setup_file,
                serde_json::to_string_pretty(&transcript).unwrap(),
            )
            .with_context(|| {
                format!("Writing FROST setup file '{}' failed", setup_file.display())
            })?;
            elog!(@info "Starting setup round 1: Adding devices");
            elog!(@suggestion "Communicate {} to the next device and run `gun setup frost add <path-to-directory-containing-frost-setup.json>`", setup_file.display());
            elog!(@suggestion "Load {} back on this device and press enter when ready", setup_file.display());
            let mut transcript = read_transcript(setup_file, false, |transcript: &Transcript| {
                if transcript.n_signers() >= threshold {
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
            (setup_file, transcript, state)
        }
        FrostSetup::Add { working_dir } => {
            if !working_dir.exists() {
                return Err(anyhow!(
                    "working directory {} doesn't exist",
                    working_dir.display()
                ));
            }
            let mut transcript = read_transcript(setup_file, true, |_: &Transcript| true);
            let my_poly = ScalarPoly::random(transcript.threshold, &mut rand::thread_rng());

            let state = transcript.add_signer(my_poly);
            std::fs::write(
                setup_file,
                serde_json::to_string_pretty(&transcript).unwrap(),
            )
            .with_context(|| {
                format!("Writing FROST setup file '{}' failed", setup_file.display())
            })?;

            elog!(@magic "Device registered as part of signing set at index {}", state.my_signer_index);
            let state = if transcript.round2_ready()
                && !cmd::read_yn("Would you like to add more devices?")
            {
                transcript.start_round_two(state)?
            } else {
                elog!(@suggestion "Ok press enter once you've finished adding devices and have loaded {}", setup_file.display());
                transcript = read_transcript(setup_file, false, |transcript: &Transcript| {
                    if transcript.n_signers() >= transcript.threshold {
                        if !transcript.round2_started() {
                            cmd::read_yn(&format!(
                                "You've added {} signing devices. Are you sure you've finished?",
                                transcript.n_signers()
                            ))
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

            (setup_file, transcript, state)
        }
    };

    std::fs::write(
        setup_file,
        serde_json::to_string_pretty(&transcript).unwrap(),
    )
    .with_context(|| format!("Writing FROST setup file '{}' failed", setup_file.display()))?;
    elog!(@magic "We've contributed our secret shares.");

    if !transcript.missing_shares().is_empty() {
        elog!(@info "We still need secret shares from {}", transcript.missing_shares().into_iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", "));
        elog!(@suggestion "Fill in {} with the other devices and press ENTER when ready.", setup_file.display());
        transcript = read_transcript(setup_file, false, |transcript: &Transcript| {
            let missing_shares = transcript.missing_shares();
            if missing_shares.is_empty() {
                true
            } else {
                elog!(@user_error "'{}' is missing shares from devices [{}]", setup_file.display(), missing_shares.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "));
                false
            }
        });
    }
    let keygen_output = transcript.finish_round_two(state)?;

    elog!(@magic "Key generation complete. We've collected secret shares from all the other parties!");
    Ok(keygen_output)
}

#[derive(Debug, Clone)]
pub struct FrostSigner {
    pub joint_key: JointKey,
    pub my_signer_index: usize,
    pub secret_share: Scalar,
    pub my_poly_secret: Scalar,
    pub working_dir: PathBuf,
    pub db: GunDatabase,
    pub network: Network,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NonceSpec {
    pub nonce_hint: usize,
    pub signer_nonce: Nonce,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FrostInputPartyShare {
    pub nonce_key_pair: NonceKeyPair,
    pub signature_shares: Vec<(usize, Scalar<Public, Zero>)>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FrostTranscript {
    pub psbt: Psbt,
    pub initiator_index: usize,
    /// For each input_index a BTreeMap (signer_index, Nonce)
    pub signer_set: BTreeMap<usize, BTreeMap<usize, NonceSpec>>,
    /// For each input_index a BTreeMap (signer_index, secret_share)
    pub signature_shares: BTreeMap<usize, BTreeMap<usize, Scalar<Public, Zero>>>,
}

impl FrostTranscript {
    pub fn missing_signatures(&self) -> BTreeSet<usize> {
        if !self.signature_shares.keys().eq(self.signer_set.keys()) {
            return self
                .signer_set
                .values()
                .next()
                .unwrap()
                .keys()
                .cloned()
                .collect();
        }

        self.signer_set
            .values()
            .map(|bt| bt.keys().cloned().collect::<BTreeSet<_>>())
            .zip(
                self.signature_shares
                    .values()
                    .map(|bt| bt.keys().cloned().collect::<BTreeSet<_>>()),
            )
            .map(|(signers, has_signed)| {
                signers.difference(&has_signed).cloned().collect::<Vec<_>>()
            })
            .flatten()
            .collect()
    }

    pub fn new(
        initiator_index: usize,
        psbt: Psbt,
        signer_set: BTreeMap<usize, BTreeMap<usize, NonceSpec>>,
    ) -> anyhow::Result<Self> {
        let signature_shares = signer_set
            .keys()
            .map(|input_index| (*input_index, BTreeMap::new()))
            .collect();
        Ok(FrostTranscript {
            psbt,
            initiator_index,
            signer_set,
            signature_shares,
        })
    }

    fn get_frost_session(
        &self,
        frost: &Frost<Schnorr<Sha256, Deterministic<Sha256>>, Sha256>,
        joint_key: &JointKey,
        input_index: usize,
    ) -> anyhow::Result<SignSession> {
        let input_public_nonces = self.signer_set.get(&input_index).expect("should exist");
        let tx_digest = message_from_psbt(&self.psbt, input_index)?;
        let message = Message::<Public>::raw(&tx_digest);
        let public_nonces = input_public_nonces
            .iter()
            .map(|(index, nonce)| (*index, nonce.signer_nonce))
            .collect::<Vec<_>>();
        Ok(frost.start_sign_session(joint_key, &public_nonces[..], message))
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
        secret_share: &Scalar,
        my_poly_secret: &Scalar,
    ) -> anyhow::Result<()> {
        let frost = Frost::<Schnorr<Sha256, Deterministic<Sha256>>, Sha256>::default();
        let tweaked_joint_key = Self::get_tweaked_key(joint_key);
        let sessions = self
            .signer_set
            .iter()
            .map(|(input_index, _)| {
                self.get_frost_session(&frost, &tweaked_joint_key, *input_index)
            })
            .collect::<Result<Vec<_>, _>>()?;

        for ((input_index, nonce_specs), session) in self.signer_set.iter().zip(sessions) {
            let nonce_spec = nonce_specs
                .get(&my_signer_index)
                .ok_or(anyhow!("you're not signing for this one"))?;

            let nonce_keypair = frost.gen_nonce(
                joint_key,
                my_signer_index,
                my_poly_secret,
                &[
                    self.initiator_index.to_be_bytes(),
                    nonce_spec.nonce_hint.to_be_bytes(),
                ]
                .concat(),
            );

            if nonce_keypair.public() != nonce_spec.signer_nonce {
                return Err(anyhow!(
                    "My nonce (signer index {}) didn't match initiator's nonce (signer index {})",
                    my_signer_index,
                    self.initiator_index
                ));
            }

            let my_sig_share = frost.sign(
                &tweaked_joint_key,
                &session,
                my_signer_index,
                secret_share,
                nonce_keypair,
            );

            self.signature_shares
                .entry(*input_index)
                .or_insert_with(BTreeMap::new)
                .insert(my_signer_index, my_sig_share);
        }

        Ok(())
    }

    pub fn finish(mut self, joint_key: &JointKey) -> anyhow::Result<Psbt> {
        let frost = Frost::<Schnorr<Sha256, Deterministic<Sha256>>, Sha256>::default();
        let joint_key = Self::get_tweaked_key(joint_key);

        for (input_index, input_sig_shares) in self.signature_shares.iter() {
            let session = self.get_frost_session(&frost, &joint_key, *input_index)?;

            let sig_shares = input_sig_shares
                .iter()
                .map(|(signer_index, signature_share)| {
                    if !frost.verify_signature_share(
                        &joint_key,
                        &session,
                        *signer_index,
                        *signature_share,
                    ) {
                        return Err(anyhow!(
                            "The signature share from signer {} was invalid",
                            signer_index
                        ));
                    }
                    Ok(*signature_share)
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

pub fn get_psbt_input_indexes(psbt: &Psbt, joint_key: &JointKey) -> Vec<usize> {
    let our_key: XOnlyPublicKey = joint_key.public_key().to_xonly().into();
    psbt.inputs
        .iter()
        .enumerate()
        .filter(|(_, input)| input.tap_internal_key == Some(our_key))
        .map(|(i, _)| i)
        .collect::<Vec<_>>()
}

impl FrostSigner {
    fn _sign(&self, psbt: &mut Psbt) -> anyhow::Result<()> {
        let possible_signers = (0..self.joint_key.n_signers())
            .filter(|i| *i != self.my_signer_index)
            .map(|x| x.to_string())
            .collect::<Vec<_>>();
        elog!(@question "Which other signers are going to sign? Choose {} out of [{}].", self.joint_key.threshold() - 1, possible_signers.join(", "));
        let coalition = loop {
            let mut signers = String::new();
            std::io::stdin().read_line(&mut signers)?;
            let signers = signers
                .trim()
                .split(' ')
                .map(|signer| usize::from_str(signer))
                .collect::<Result<BTreeSet<_>, _>>();

            if let Ok(mut signers) = signers {
                signers.insert(self.my_signer_index);
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

        let input_indexes = get_psbt_input_indexes(&psbt, &self.joint_key);
        let mut signer_nonce_set = BTreeMap::new();
        for index in input_indexes {
            signer_nonce_set.insert(index, self.db.fetch_and_increment_nonces(&coalition)?);
        }

        let mut transcript =
            FrostTranscript::new(self.my_signer_index, psbt.clone(), signer_nonce_set)?;
        transcript.contribute(
            &self.joint_key,
            self.my_signer_index,
            &self.secret_share,
            &self.my_poly_secret,
        )?;

        let txid = psbt.clone().extract_tx().txid();
        let frost_transcript_file = self.working_dir.join(format!("{}.frost", txid));

        while let Err(e) = std::fs::write(
            &frost_transcript_file,
            serde_json::to_string(&transcript).unwrap(),
        ) {
            elog!(@user_error "Failed to write frost signing session to {}: {}", frost_transcript_file.display(), e);
            elog!(@suggestion "Press ENTER to try again.");
            let _ = std::io::stdin().read_line(&mut String::new());
        }

        elog!(@magic "Frost signing session written to {}", frost_transcript_file.display());
        let missing_signers = transcript.missing_signatures();
        elog!(@suggestion "Pass session to signing devices [{}] and press enter when you have returned it.", missing_signers.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "));

        let read_transcript = read_transcript(
            frost_transcript_file.as_path(),
            false,
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

        transcript.signature_shares = read_transcript.signature_shares;

        *psbt = transcript.finish(&self.joint_key)?;

        elog!(@magic "Finished signing {}", txid);

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
        if !cmd::read_yn(&format!(
            "This is the transaction that will be saved for signing.\n{}Ok",
            cmd::display_psbt(self.network, psbt)
        )) {
            return Err(SignerError::UserCanceled);
        }

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
