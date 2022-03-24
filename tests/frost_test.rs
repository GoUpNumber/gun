use std::collections::{BTreeSet, BTreeMap};
use std::str::FromStr;
use bdk::blockchain::noop_progress;
use bdk::wallet::AddressIndex;
use bdk::{testutils::blockchain_tests::TestClient, blockchain::EsploraBlockchain};
use bdk::Wallet;
use bitcoin::{
    consensus::deserialize, hashes::hex::FromHex, util::psbt::PartiallySignedTransaction, Network,
};
use gun_wallet::database::RemoteNonces;
use gun_wallet::frost::KeyGenOutput;
use gun_wallet::{
    database::GunDatabase,
    frost::{FrostTranscript, Transcript},
};
use bitcoin::Address;
use schnorr_fun::{frost::ScalarPoly, fun::s};

#[test]
fn test_frost() -> anyhow::Result<()> {
    let mut test_client = TestClient::default();


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

    let KeyGenOutput {
        secret_share: ss1,
        joint_key,
        nonces: nonces1,
        network,
        ..
    } = transcript.clone().finish_round_two(state1).unwrap();
    let KeyGenOutput { secret_share: ss2, ..   } = transcript.clone().finish_round_two(state2).unwrap();
    let KeyGenOutput { secret_share: ss3, .. } = transcript.finish_round_two(state3).unwrap();



    let wallet = {
        let external = format!("tr({})", joint_key.public_key());
        let db = bdk::sled::Config::new()
            .temporary(true)
            .flush_every_ms(None)
            .open()
            .unwrap()
            .open_tree("test")
            .unwrap();

        let esplora_url = format!(
            "http://{}",
            test_client.electrsd.esplora_url.as_ref().unwrap()
        );
        let esplora = EsploraBlockchain::new(&esplora_url, 5);


        let wallet = Wallet::new(&external, None, network, db, esplora)?;
        let funding_address = wallet.get_address(AddressIndex::New).unwrap().address;

        test_client.generate(1, Some(funding_address));
        test_client.generate(100, None);

        while wallet.get_balance()? < 100_000 {
            std::thread::sleep(core::time::Duration::from_millis(1_000));
            wallet.sync(noop_progress(), None)?;
            println!("syncing done on party -- checking balance");
        }
        wallet
    };

    let mut builder = wallet.build_tx();
    builder.add_recipient(Address::from_str("bcrt1qngw83fg8dz0k749cg7k3emc7v98wy0c7azaa6h").unwrap().script_pubkey(), 50_000);
    let (mut psbt, details) = builder.finish()?;

    let signers = {
        let mut signers = BTreeMap::new();
        signers.insert(0, NonceSpec { signer_nonce: nonces1[0][0], nonce_hint: 0 });
        signers.insert(2, NonceSpec { signer_nonce: nonces1[2][0], nonce_hint: 0 });
        signers
    };

    let frost_transcript = FrostTranscript::new(0, psbt, &joint_key,signers);

    Ok(())


    // // Generate nonces
    // let gun_db = GunDatabase::test_new();
    // // Do something

    // // Random PSBT i know nothing about
    // let psbt = deserialize(&Vec::from_hex(&"70736274ff0100a00200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40000000000feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac000000000001076a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf1336f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa882920001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb82308000000".to_string()).unwrap()[..]).unwrap();

    // let frost_transcript = FrostTranscript::new(
    //     0,
    //     psbt,
    //     &keygenstate.joint_key,
    //     &gun_db,
    //     BTreeSet::from([0, 1]),
    // )
    // .unwrap();

    // // frost_transcript.contribute(
    // //     &keygenstate.joint_key,
    // //     0,
    // //     0,
    // //     &state1.secret_share,
    // //     &state1.my_poly_secret,
    // // );

    // dbg!(frost_transcript);
}
