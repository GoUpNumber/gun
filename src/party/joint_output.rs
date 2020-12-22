use anyhow::anyhow;
use bdk::{
    bitcoin::{secp256k1::SecretKey, Network, PrivateKey, PublicKey},
    blockchain::Blockchain,
    database::MemoryDatabase,
    descriptor::ExtendedDescriptor,
    keys::DescriptorSinglePub,
    miniscript::policy::concrete::Policy,
    signer::{SignerId, SignerOrdering},
    Wallet,
};
use miniscript::{Descriptor, DescriptorPublicKey};
use olivia_secp256k1::fun::{g, marker::*, rand_core::RngCore, s, Point, Scalar, G};
use std::{convert::TryInto, sync::Arc};

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq)]
pub enum Either<T> {
    Left(T),
    Right(T),
}

impl<T> Either<T> {
    pub fn swap(self) -> Self {
        match self {
            Either::Left(t) => Either::Right(t),
            Either::Right(t) => Either::Left(t),
        }
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq)]
pub struct JointOutput {
    pub output_keys: [Point; 2],
    pub my_key: Either<Scalar>,
}

impl JointOutput {
    pub fn new(
        public_keys: [Point<EvenY>; 2],
        my_key: Either<Scalar>,
        anticipated_signatures: [Point<impl PointType, Public, Zero>; 2],
        offer_choose_right: bool,
        rng: &mut chacha20::ChaCha20Rng,
    ) -> Self {
        let (r1, r2) = (Scalar::random(rng), Scalar::random(rng));
        let (left, right) = (&anticipated_signatures[0], &anticipated_signatures[1]);
        let (proposal_key, offer_key) = (&public_keys[0], &public_keys[1]);

        let mut output_keys = match offer_choose_right {
            true => vec![
                g!(proposal_key + left + r1 * G),
                g!(offer_key + right + r2 * G),
            ],
            false => vec![
                g!(proposal_key + right + r1 * G),
                g!(offer_key + left + r2 * G),
            ],
        };

        let mut my_key = match my_key {
            Either::Left(key) => {
                debug_assert!(&g!(key * G) == proposal_key, "secret key wasn't correct");
                Either::Left(s!(key + r1).mark::<NonZero>().unwrap())
            }
            Either::Right(key) => {
                debug_assert!(&g!(key * G) == offer_key, "secret key wasn't correct");
                Either::Right(s!(key + r2).mark::<NonZero>().unwrap())
            }
        };

        let swap = {
            let mut byte = [0u8; 1];
            rng.fill_bytes(&mut byte);
            (byte[0] & 0x01) == 1
        };

        if swap {
            my_key = my_key.swap()
        };

        output_keys.rotate_right(swap as usize);

        // Since we added r1 and r2 to the sum which are both functions of offer_key and proposal_key it will never add up to zero
        let output_keys = output_keys
            .into_iter()
            .map(|k| {
                k.mark::<(Normal, NonZero)>()
                    .expect("computionally unreachable")
            })
            .collect::<Vec<_>>();

        Self {
            output_keys: output_keys.try_into().unwrap(),
            my_key,
        }
    }

    pub fn descriptor(&self) -> ExtendedDescriptor {
        let policy = Policy::<DescriptorPublicKey>::Or(
            self.output_keys
                .iter()
                .map(|key| {
                    (
                        1,
                        Policy::Key(DescriptorPublicKey::SinglePub(DescriptorSinglePub {
                            origin: None,
                            key: PublicKey {
                                compressed: true,
                                key: (*key).into(),
                            },
                        })),
                    )
                })
                .collect(),
        );

        Descriptor::Wsh(policy.compile().unwrap())
    }

    pub async fn claim<B: Blockchain>(
        &self,
        blockchain: B,
        sig_scalar: Scalar<Public, Zero>,
    ) -> anyhow::Result<Wallet<B, MemoryDatabase>> {
        let mut wallet = Wallet::new(
            self.descriptor(),
            None,
            Network::Regtest,
            MemoryDatabase::default(),
            blockchain,
        )
        .await?;
        let (completed_key, public_key) = match &self.my_key {
            Either::Left(key) => (s!(key + sig_scalar), self.output_keys[0]),
            Either::Right(key) => (s!(key + sig_scalar), self.output_keys[1]),
        };

        if g!(completed_key * G) != public_key {
            return Err(anyhow!("oracle's scalar does not much what was expected"));
        }

        let secret_key = SecretKey::from(
            completed_key
                .mark::<NonZero>()
                .expect("must not be zero since it was equal to the output key"),
        );
        let priv_key = PrivateKey {
            compressed: true,
            network: Network::Regtest,
            key: secret_key,
        };
        let public_key = PublicKey {
            key: public_key.into(),
            compressed: true,
        };

        wallet.add_signer(
            bdk::KeychainKind::External,
            SignerId::PkHash(public_key.pubkey_hash().into()),
            SignerOrdering(1),
            Arc::new(priv_key),
        );
        Ok(wallet)
    }
}
