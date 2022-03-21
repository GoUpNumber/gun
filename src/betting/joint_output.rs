use bdk::{
    bitcoin::{self, PublicKey},
    descriptor::ExtendedDescriptor,
    keys::DescriptorSinglePub,
    miniscript::{descriptor::Wsh, policy::concrete::Policy, Descriptor, DescriptorPublicKey},
};
use olivia_secp256k1::fun::{g, marker::*, s, Point, Scalar, G};
use std::convert::{Infallible, TryInto};

use super::randomize::Randomize;

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

    pub fn unwrap(&self) -> &T {
        match &self {
            Either::Left(t) => t,
            Either::Right(t) => t,
        }
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq)]
pub struct JointOutput {
    pub output_keys: [Point; 2],
    pub my_key: Either<Scalar>,
    pub swapped: bool,
}

impl JointOutput {
    pub fn new(
        public_keys: [Point<EvenY>; 2],
        my_key: Either<Scalar>,
        anticipated_signatures: [Point<impl PointType, Public, Zero>; 2],
        offer_choose_right: bool,
        Randomize {
            r1,
            r2,
            swap_points,
        }: Randomize,
    ) -> Self {
        let (left, right) = (anticipated_signatures[0], anticipated_signatures[1]);
        let (proposal_key, offer_key) = (&public_keys[0], &public_keys[1]);

        // These unwraps are safe -- we added r1 and r2 to the sum which are both functions of offer_key and
        // proposal_key it will never add up to zero.
        let output_keys = match offer_choose_right {
            false => vec![
                g!(proposal_key + right + r1 * G)
                    .mark::<(Normal, NonZero)>()
                    .unwrap(),
                g!(offer_key + left + r2 * G)
                    .mark::<(Normal, NonZero)>()
                    .unwrap(),
            ],
            true => vec![
                g!(proposal_key + left + r1 * G)
                    .mark::<(Normal, NonZero)>()
                    .unwrap(),
                {
                    let point = g!(offer_key + right + r2 * G);
                    point.mark::<(Normal, NonZero)>().unwrap()
                },
            ],
        };

        let my_key = match my_key {
            Either::Left(key) => {
                debug_assert!(&g!(key * G) == proposal_key, "secret key wasn't correct");
                Either::Left(s!(key + r1).mark::<NonZero>().unwrap())
            }
            Either::Right(key) => {
                debug_assert!(&g!(key * G) == offer_key, "secret key wasn't correct");
                Either::Right(s!(key + r2).mark::<NonZero>().unwrap())
            }
        };

        Self {
            output_keys: output_keys.try_into().unwrap(),
            my_key,
            swapped: swap_points,
        }
    }

    pub fn policy(&self) -> Policy<bitcoin::PublicKey> {
        let keys = &match self.swapped {
            false => self.output_keys,
            true => [self.output_keys[1], self.output_keys[0]],
        };

        Policy::<bitcoin::PublicKey>::Or(
            keys.iter()
                .map(|key| {
                    (
                        1,
                        Policy::Key(PublicKey {
                            compressed: true,
                            key: (*key).into(),
                        }),
                    )
                })
                .collect(),
        )
    }

    // pub fn compute_privkey<B: Blockchain>(
    //     &self,
    //     sig_scalar: Either,
    // ) -> anyhow::Result<SecretKey> {
    //     let (completed_key, public_key) = match &self.my_key {
    //         Either::Left(key) => (s!(key + sig_scalar), self.output_keys[0]),
    //         Either::Right(key) => (s!(key + sig_scalar), self.output_keys[1]),
    //     };

    //     if g!(completed_key * G) != public_key {
    //         return Err(anyhow!("oracle's scalar does not much what was expected"));
    //     }

    //     Ok(completed_key
    //         .mark::<NonZero>()
    //         .expect("must not be zero since it was equal to the output key")
    //         .into())
    // }

    pub fn my_point(&self) -> &Point {
        match self.my_key {
            Either::Left(_) => &self.output_keys[0],
            Either::Right(_) => &self.output_keys[1],
        }
    }

    pub fn wallet_descriptor(&self) -> ExtendedDescriptor {
        let compiled_policy = self
            .policy()
            .translate_pk(&mut |pk: &bitcoin::PublicKey| -> Result<_, Infallible> {
                Ok(DescriptorPublicKey::SinglePub(DescriptorSinglePub {
                    origin: None,
                    key: miniscript::descriptor::SinglePubKey::FullKey(*pk),
                }))
            })
            .unwrap()
            .compile()
            .unwrap();
        Descriptor::Wsh(Wsh::new(compiled_policy).unwrap())
    }

    pub fn descriptor(&self) -> Descriptor<bitcoin::PublicKey> {
        Descriptor::Wsh(Wsh::new(self.policy().compile().unwrap()).unwrap())
    }
}
