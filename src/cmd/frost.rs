use crate::cmd;
use crate::cmd::FrostSetup;
use crate::database::GunDatabase;
use crate::elog;
use anyhow::{anyhow, Context};
use bdk::signer::Signer;
use bitcoin::Network;
use bitcoin::hashes::Hash;
use bitcoin::schnorr::XOnlyPublicKey;
use bitcoin::secp256k1::{Secp256k1, All};
use bitcoin::util::taproot::TapTweakHash;
use chacha20::cipher::StreamCipher;
use olivia_secp256k1::schnorr_fun::musig::NonceKeyPair;
use rand::{CryptoRng, RngCore};
use schnorr_fun::{frost::*, Schnorr};
use schnorr_fun::{
    frost::{PointPoly, ScalarPoly},
    musig::Nonce,
    fun::{marker::*, Point, Scalar},
    nonce::Deterministic
};
use bitcoin::util::psbt::PartiallySignedTransaction as Psbt;
use serde::{Serialize, Deserialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::{
    fs::File,
    path::{Path},
    collections::BTreeMap
};
use crate::ecdh_frost as ecdh;
use crate::ecdh_frost::KeyPair;

use super::CommonArgs;

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

pub fn add_signer(transcript: &mut Transcript, my_poly: ScalarPoly) -> State1 {
    transcript.signers.push(my_poly.to_point_poly());
    State1 {
        my_poly,
        my_signer_index: transcript.signers.len() - 1,
    }
}


pub fn start_round_two(
    transcript: &mut Transcript,
    State1 {
        my_poly,
        my_signer_index,
    }: State1,
) -> anyhow::Result<State2> {
    let commitment_digest = transcript.commitment_digest();
    let frost = Frost::<Schnorr<Sha256, Deterministic<Sha256>>>::default();
    if transcript.signers[my_signer_index] != my_poly.to_point_poly() {
        return Err(anyhow!("Our first round data does not match what we expect so we must abort"));
    }
    let dkg = frost.collect_polys(transcript.signers.clone())?;
    let my_poly_secret = my_poly.first_coef().clone();
    let shares = frost.create_shares(&dkg, my_poly);

    let encrypted_shares = transcript
        .signers
        .iter()
        .enumerate()
        .filter(|(i,_)| *i != my_signer_index)
        .map(|(i, poly)| {
            EncryptedShare::new(
                poly.points()[0].into_point_with_even_y().0,
                &mut rand::thread_rng(),
                &shares[i],
                &commitment_digest,
            )
        })
        .collect();

    while transcript.shares.len() <= my_signer_index {
        transcript.shares.push(vec![])
    }
    transcript.shares[my_signer_index] = encrypted_shares;



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
    transcript: Transcript,
    State2 {
        my_poly_secret,
        my_signer_index,
        my_share,
        dkg,
        commitment_digest,
        frost,
    }: State2,
) -> anyhow::Result<(Scalar, JointKey, usize)> {
    if commitment_digest != transcript.commitment_digest() {
        return Err(anyhow!("transcript has been maliciously modified"));
    }

    let missing_shares = transcript.missing_shares();

    if !missing_shares.is_empty() {
        return Err(anyhow!("transcript is missing shares"));
    }

    let keypair = KeyPair::from_secret_key(my_poly_secret);

    let mut shares = transcript
        .shares
        .iter()
        .enumerate()
        .map(|(i, encrypted_shares)| {
            if i == my_signer_index {
                return my_share.clone()
            }
            let offset = (my_signer_index > i) as usize;
            let encrypted_share = encrypted_shares[my_signer_index - offset].clone();
            encrypted_share.decrypt(&keypair, &commitment_digest)
        })
        .collect();

    let (secret_share, joint_key) = frost.collect_shares(dkg, my_signer_index, shares)?;


    Ok((secret_share, secret_share, my_signer_index))
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct Transcript {
    pub threshold: usize,
    pub network: Network,
    pub signers: Vec<PointPoly>,
    pub initiators: Vec<usize>,
    pub shares: Vec<Vec<EncryptedShare>>,
    pub nonces: Vec<Vec<Nonce>>,
}

impl Transcript {
    pub fn new(threshold: usize, network: Network) -> Self {
        Self {
            threshold,
            signers: vec![],
            initiators: vec![],
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
        self.shares
            .iter()
            .enumerate()
            .filter(|(_, v)| v.len() < self.n_signers())
            .map(|(i, _)| i)
            .chain(self.shares.len() - 1..self.n_signers())
            .collect()
    }
}

fn read_transcript(path: &Path, validate: impl Fn(&Transcript) -> bool) -> Transcript {
    loop {
        match File::open(path) {
            Ok(file) => match serde_json::from_reader::<_, Transcript>(file) {
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

pub fn run_frost_setup(
    wallet_dir: &Path,
    setup_file: &Path,
    frost_setup: FrostSetup,
) -> anyhow::Result<((usize, Scalar), JointKey, Network)> {

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

            let n_nonces = 50;

            let mut transcript = Transcript::new(threshold, network);
            let my_poly = ScalarPoly::random(threshold, &mut rand::thread_rng());
            let public_poly = my_poly.to_point_poly();

            let state = add_signer(&mut transcript, my_poly);
            elog!(@info "Starting setup round 1: Adding devices");
            elog!(@suggestion "Communicate {} to the next device and run `gun setup forst add <path-to-directory-containing-frost-setup.json>`", setup_file.display());
            elog!(@suggestion "Load {} back on this device and press enter when ready", setup_file.display());
            let mut transcript = read_transcript(setup_file, |transcript| {
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

            let state = start_round_two(&mut transcript, state)?;
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
            let mut transcript = read_transcript(setup_file, |transcript| {
                let missing_shares = transcript.missing_shares();
                if missing_shares.is_empty() {
                    true
                } else {
                    elog!(@user_error "'{}' is missing shares for devices at indexes {}", setup_file.display(), missing_shares.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "));
                    false
                }
            });
            let (secret_share, joint_key, my_index) = finish_round_two(transcript, state)?;
            Ok(((my_index, secret_share), joint_key, network))
        }
        FrostSetup::Add { working_dir } => {

            if !working_dir.exists() {
                return Err(anyhow!(
                    "working directory {} doesn't exist",
                    working_dir.display()
                ));
            }
            let mut transcript = read_transcript(setup_file, |_| true);
            let network = transcript.network;
            let my_poly = ScalarPoly::random(transcript.threshold, &mut rand::thread_rng());

            let state = add_signer(&mut transcript, my_poly);
            elog!(@celebration "Device successfully registered");
            let state = if transcript.round2_ready()
                && !cmd::read_yn("Would you like to add more devices?")
            {
                start_round_two(&mut transcript, state)?
            } else {
                let mut transcript = read_transcript(setup_file, |transcript| {
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
                start_round_two(&mut transcript, state)?
            };

            elog!(@info "Starting setup round 2: Generate secret shares");
            elog!(@suggestion "Communicate the updated {} to the next device", setup_file.display());
            elog!(@suggestion "Load {} back on this device and press enter when ready", setup_file.display());
            let mut transcript = read_transcript(setup_file, |transcript| {
                let missing_shares = transcript.missing_shares();
                if missing_shares.is_empty() {
                    true
                } else {
                    elog!(@user_error "'{}' is missing shares for devices at indexes {}", setup_file.display(), missing_shares.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "));
                    false
                }
            });
            let (secret_share, joint_key, my_index) = finish_round_two(transcript, state)?;
            Ok(((my_index, secret_share), joint_key, network))
        }
    }
}

#[derive(Debug, Clone)]
pub struct FrostSigner {
   pub joint_key: JointKey,
   pub my_index: usize,
   pub secret_share: Scalar,
   pub working_dir: PathBuf,
   pub db: GunDatabase
}


#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FrostSignTranscript {
    pub public_nonces: Vec<(usize, Nonce)>,
    pub signature_shares: Vec<Scalar<Public, Zero>>
}


use bdk::wallet::signer::SignerError;
pub fn message_from_psbt(psbt: &Psbt, input_index: usize) -> Result<[u8;32], SignerError> {
    use bitcoin::util::sighash;
    use schnorr_fun::Message;
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


impl Signer for FrostSigner {
    fn sign(
        &self,
        psbt: &mut Psbt,
        input_index: Option<usize>,
        secp: &Secp256k1<All>,
    ) -> Result<(), bdk::signer::SignerError> {
        let our_key: XOnlyPublicKey = self.joint_key.public_key().to_xonly().into();
        let our_inputs = psbt.inputs.iter().filter(|input| input.tap_internal_key == Some(our_key));
        let tweak = Scalar::from_bytes_mod_order(TapTweakHash::from_key_and_tweak(our_key, None).into_inner());
        let joint_key = self.joint_key.tweak(tweak);
        let frost = Frost::<Schnorr::<Sha256, Deterministic<Sha256>>, Sha256>::default();

        elog!(@question "Which signers are going to sign? Specify {} indexes seperated by spaces", joint_key.threshold());
        let coalition = loop {
            let mut signers = String::new();
            let signers = std::io::stdin().read_line(&mut signers);
            let signers = signers.split(' ').map(|signer| usize::from_str(signer)).collect::<Result<BtreeSet<_>,_>>();
            if let Ok(signers) = signers {
                if signers.iter().all(|signer| signer < joint_key.n_signers()) && signers.len() == joint_key.threshold() {
                    break signers
                }
                else {
                    elog!(@user_error "Invalid signer list try again");
                }
            }
            else {
                elog!(@user_error "Invalid signer list try again");
            }
        };


        for (input_index, inputs) in psbt.inputs.iter().enumerate() {
            use schnorr_fun::Message;
            let message = Message::<Public>::raw(&message_from_psbt(&psbt, input_index)?);
            let my_curr_index = self.db.get_entity::<FrostLocalCounter>(())?.unwrap_or(0);
            let my_nonces = nonce_gen(&frost.schnorr, self.secret_share, signer_index, my_curr_index);

            coalition.iter().map(|signer_index| self.db.get_entity::<RemoteNonces>(signer_index)?.get())
            loop {
                if !self.working_dir.exists() {
                    elog!(@user_error "FROST working directory {} does not exists (Maybe you need to insert your SD card?)", self.working_dir.display());
                } else {

                }
            };


            let session = frost.start_sign_session(&joint_key, nonces: todo!(), message);

            session.sign(&joint_key, &session, self.my_index, &self.secret_share, )
        };

        // apply
        // for input in our_inputs {

        // }
        todo!()
    }

    fn sign_whole_tx(&self) -> bool {
        true
    }

    fn id(&self, secp: &Secp256k1<All>) -> bdk::signer::SignerId {
        bdk::signer::SignerId::XOnly(self.joint_key.public_key().to_xonly().into())
    }
}


pub fn nonce_gen(nonce_gen: &Deterministic<Sha256>, secret_share: &Scalar, initiator_index: usize, local_counter: usize) -> NonceKeyPair {
    use schnorr_fun::fun::derive_nonce;
    let r1 = derive_nonce!(
            nonce_gen => nonce_gen,
            secret => secret_share,
            public => [ b"r1-frost", initiator_index.to_be_bytes(), index.to_be_bytes()]
        );
        let r2 = derive_nonce!(
            nonce_gen => nonce_gen,
            secret => secret_share,
            public => [ b"r2-frost", initiator_index.to_be_bytes(), index.to_be_bytes()]
        );
        let R1 = g!(r1 * G).normalize();
        let R2 = g!(r2 * G).normalize();
        NonceKeyPair {
            public: Nonce([R1, R2]),
            secret: [r1, r2],
        }

}
