use std::collections::BTreeSet;

use bitcoin::{
    consensus::deserialize, hashes::hex::FromHex, util::psbt::PartiallySignedTransaction, Network,
};
use gun_wallet::{
    database::GunDatabase,
    frost::{FrostTranscript, Transcript},
};
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

    let keygenstate = transcript.clone().finish_round_two(state1).unwrap();
    let _ = transcript.clone().finish_round_two(state2).unwrap();
    let _ = transcript.finish_round_two(state3).unwrap();

    // Generate nonces
    let gun_db = GunDatabase::test_new();
    // Do something

    // Random PSBT i know nothing about
    let psbt = deserialize(&Vec::from_hex(&"70736274ff0100a00200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40000000000feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac000000000001076a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf1336f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa882920001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb82308000000".to_string()).unwrap()[..]).unwrap();

    let frost_transcript = FrostTranscript::new(
        0,
        psbt,
        &keygenstate.joint_key,
        &gun_db,
        BTreeSet::from([0, 1]),
    )
    .unwrap();

    // frost_transcript.contribute(
    //     &keygenstate.joint_key,
    //     0,
    //     0,
    //     &state1.secret_share,
    //     &state1.my_poly_secret,
    // );

    dbg!(frost_transcript);
}
