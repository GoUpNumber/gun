use bitcoin::Network;
use gun_wallet::frost::Transcript;
use schnorr_fun::{frost::ScalarPoly, fun::s};

#[test]
fn test_frost() {
    let mut transcript = Transcript::new(2, Network::Regtest);
    let sp1 = ScalarPoly::new(vec![s!(3), s!(7)]);
    let sp2 = ScalarPoly::new(vec![s!(11), s!(13)]);
    let sp3 = ScalarPoly::new(vec![s!(17), s!(19)]);

    let state1 = transcript.add_signer(sp1);
    let state2 = transcript.add_signer(sp2);
    let state3 = transcript.add_signer(sp3);

    let state1 = transcript.start_round_two(state1).unwrap();
    let state2 = transcript.start_round_two(state2).unwrap();
    let state3 = transcript.start_round_two(state3).unwrap();

    let _ = transcript.clone().finish_round_two(state1).unwrap();
    let _ = transcript.clone().finish_round_two(state2).unwrap();
    let _ = transcript.finish_round_two(state3).unwrap();
}
