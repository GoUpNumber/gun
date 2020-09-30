use crate::{change::Change, keychain::Keychain, proposal::Proposal};
use anyhow::Context;
use anyhow::anyhow;
use bdk::ScriptType;
use bdk::{
    bitcoin::{Amount, PublicKey, Script},
    blockchain::Blockchain,
    database::BatchDatabase,
    descriptor::Segwitv0,
    miniscript::policy::concrete::Policy,
    wallet::coin_selection::DumbCoinSelection,
    TxBuilder, Wallet,
};
use olivia_core::http::{EventResponse, PathResponse};
use olivia_secp256k1::schnorr_fun::fun::hex;
use olivia_secp256k1::{
    schnorr_fun::fun::{
        g,
        marker::*,
        rand_core::{CryptoRng, RngCore},
        Point, Scalar, XOnly, G,
    },
    Secp256k1,
};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum Witness {
    P2WPKH((Point, ecdsa_fun::Signature)),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct SignedInput {
    outpoint: bdk::bitcoin::OutPoint,
    witness: Witness,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct OfferInfo {
    pub inputs: Vec<SignedInput>,
    pub change: Option<Change>,
}

impl OfferInfo {
    pub fn to_string(&self) -> String {
        format!("{}", crate::encode::serialize(self))
    }
}
// pub Offer {
//     pub fn encrypt_to(&self,remote: &XOnly, keypair: &ecdh::KeyPair) -> Vec<u8> {
//         let mut prng = ecdh::generate_prf(keypair, remote);
//         out.extend(keypair.public_key.to_xonly().to_bytes());

//     }

// }

pub async fn make_offer(
    keychain: &Keychain,
    wallet: &Wallet<impl Blockchain, impl BatchDatabase>,
    proposal: Proposal,
    choose_left: bool,
    amount: Amount,
) -> anyhow::Result<OfferInfo> {
    let oracle_info = crate::reqwest::get(&format!("http://{}", proposal.oracle))
        .await?
        .json::<PathResponse<Secp256k1>>()
        .await?;
    let public_key = XOnly::from(oracle_info.public_key.ok_or(anyhow!(
        "oracle {} didn't return a public key",
        proposal.oracle
    ))?)
    .to_point();
    let url =
        crate::reqwest::Url::parse(&format!("http://{}{}", proposal.oracle, proposal.event_id))?;
    let event_response = crate::reqwest::get(url.clone())
        .await?
        .json::<EventResponse<Secp256k1>>()
        .await
        .map_err(|e| {
            anyhow!(
                "URL ({}) did not return a valid JSON event description: {}",
                &url,
                e
            )
        })?;

    let event_id = &proposal.event_id;
    let remote_public_key = &proposal.payload.public_key;
    let nonce = XOnly::from(event_response.announcement.nonce).to_point();

    let outcomes = event_id
        .binary_outcomes()
        .ok_or(anyhow!("{} is not a binary event type", event_id))?;

    let mut anticpated_signatutes = outcomes.iter().map(|outcome| {
        olivia_secp256k1::anticipate_signature(&public_key, &nonce, event_id, outcome)
    });

    let local_keypair = keychain.keypair_for_offer(&proposal);

    let (mut _cipher, mut rng) = crate::ecdh::ecdh(&local_keypair, remote_public_key);

    let one_of_two = create_joint_output(
        &remote_public_key,
        &local_keypair.public_key,
        &(
            anticpated_signatutes.next().unwrap(),
            anticpated_signatutes.next().unwrap(),
        ),
        choose_left,
        &mut rng,
    );



    let output_value = amount
        .checked_add(proposal.value)
        .ok_or(anyhow!("BTC amount overflow"))?;
    let output = (one_of_two, output_value);

    let witness = create_witness(wallet, proposal, output)?;
    unimplemented!()
}

pub fn create_witness(
    wallet: &Wallet<impl Blockchain, impl BatchDatabase>,
    proposal: Proposal,
    output: (Script, Amount),
) -> anyhow::Result<Vec<Witness>> {
    let mut builder = TxBuilder::default().add_recipient(output.0, output.1.as_sat());

    for proposal_input in proposal.payload.inputs {
        builder = builder.add_utxo(proposal_input)
    }

    if let Some(change) = proposal.payload.change {
        builder = builder.add_recipient(change.script().clone(), change.value());
    }

    let (psbt, _tx_details) = wallet.create_tx::<DumbCoinSelection>(builder).context("Unable to create offer transaction")?;
    let (psbt, is_final) = wallet.sign(psbt, None).context("Unable to sign offer transaction")?;
    assert!(
        !is_final,
        "we haven't got the other party's signature so it can't be final here"
    );

    unimplemented!("here")
}

pub fn create_joint_output<Rng: RngCore + CryptoRng>(
    proposal_key: &Point<impl PointType>,
    offer_key: &Point<impl PointType>,
    (left, right): &(
        Point<impl PointType, Public, Zero>,
        Point<impl PointType, Public, Zero>,
    ),
    offer_choose_left: bool,
    rng: &mut Rng,
) -> Script {
    let (r1, r2) = (Scalar::random(rng), Scalar::random(rng));

    let mut output_keys = match offer_choose_left {
        true => vec![
            g!(offer_key + left + r1 * G),
            g!(proposal_key + right + r2 * G),
        ],
        false => vec![
            g!(proposal_key + left + r1 * G),
            g!(offer_key + right + r2 * G),
        ],
    };

    let mut byte = [0u8; 1];
    rng.fill_bytes(&mut byte);
    output_keys.rotate_right((byte[0] & 0x01) as usize);

    let policy = Policy::<PublicKey>::Or(
        output_keys
            .into_iter()
            .map(|key| {
                (
                    1,
                    Policy::Key(PublicKey {
                        compressed: false,
                        key: key
                            .mark::<(Normal, NonZero)>()
                            .expect("cannot be zero since unpredictable random factor was added")
                            .into(),
                    }),
                )
            })
            .collect(),
    );
    policy.compile::<Segwitv0>().unwrap().encode().to_v0_p2wsh()
}
