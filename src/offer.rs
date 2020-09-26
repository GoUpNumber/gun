pub enum Witness {
    P2WPKH((Point, ecdsa_fun::Signature))
}


impl Witness {
    fn encode(&self) -> Vec<u8> {
        match self {
            Witness::P2WPKH((point, signature)) => {
                let mut out = Vec::with_capacity(1 + 33 + 64);
                out.push(0x00);
                out.extend_from_slice(point.to_bytes().as_slice());
                out.extend_from_slice(signature.to_bytes().as_slice());
                out
            }
        }
    }

    fn decode(&self, buf: &mut Vec<u8>) -> Result<Witness, ()> {
        match buf.remove(0) {
            0x00 => {
                buf.drain(..33)
            }
        }
    }
}


pub struct SignedInput {
    outpoint: magical::bitcoin::OutPoint,
    witness: Witness,
}

impl Signedinput {
    fn to_bytes()
}


#[derive(Debug, Clone, PartialEq)]
pub struct OfferInfo {
    pub inputs: Vec<SignedInput>,
    pub change: Option<(u64, Script)>,
}

pub Offer {
    pub fn encrypt_to(&self,remote: &XOnly, keypair: &ecdh::KeyPair) -> Vec<u8> {
        let mut prng = ecdh::generate_prf(keypair, remote);
        let out = vec![];
        out.extend(keypair.public_key.to_xonly().to_bytes());
        for input in inputs {
            out.extend
        }
    }
}
