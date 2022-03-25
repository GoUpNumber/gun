use bdk::blockchain::{noop_progress, Broadcast};
use bdk::wallet::AddressIndex;
use bdk::{blockchain::EsploraBlockchain, testutils::blockchain_tests::TestClient};
use bdk::{SignOptions, Wallet};
use bitcoin::Address;
use bitcoin::Network;
use gun_wallet::frost::{FrostTranscript, Transcript};
use gun_wallet::frost::{KeyGenOutput, NonceSpec};
use schnorr_fun::{frost::ScalarPoly, fun::s};
use std::collections::BTreeMap;
use std::str::FromStr;

#[test]
fn test_frost() -> anyhow::Result<()> {
    let mut test_client = TestClient::default();

    let mut transcript = Transcript::new(2, Network::Regtest);
    let sp1 = ScalarPoly::new(vec![s!(3), s!(7)]);
    let sp2 = ScalarPoly::new(vec![s!(11), s!(13)]);
    let sp3 = ScalarPoly::new(vec![s!(17), s!(19)]);

    let state1 = transcript.add_signer(sp1.clone());
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
        my_poly_secret: mps1,
        ..
    } = transcript.clone().finish_round_two(state1).unwrap();

    assert_eq!(&mps1, sp1.first_coef());

    let KeyGenOutput {
        secret_share: _,
        my_poly_secret: _,
        ..
    } = transcript.clone().finish_round_two(state2).unwrap();
    let KeyGenOutput {
        secret_share: ss3,
        my_poly_secret: mps3,
        ..
    } = transcript.finish_round_two(state3).unwrap();

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
    builder.add_recipient(
        Address::from_str("bcrt1qngw83fg8dz0k749cg7k3emc7v98wy0c7azaa6h")
            .unwrap()
            .script_pubkey(),
        50_000,
    );
    let (psbt, _) = builder.finish()?;

    let nonce_specs = psbt
        .inputs
        .iter()
        .enumerate()
        .map(|(input_index, _input)| {
            let mut signers = BTreeMap::new();
            signers.insert(
                0,
                NonceSpec {
                    signer_nonce: nonces1[0][input_index],
                    nonce_hint: input_index,
                },
            );
            signers.insert(
                2,
                NonceSpec {
                    signer_nonce: nonces1[2][input_index],
                    nonce_hint: input_index,
                },
            );
            (input_index, signers)
        })
        .collect();

    let mut frost_transcript = FrostTranscript::new(0, psbt, nonce_specs)?;

    assert_eq!(
        frost_transcript.missing_signatures(),
        [0, 2].into_iter().collect()
    );
    frost_transcript.contribute(&joint_key, 0, &ss1, &mps1)?;
    assert_eq!(
        frost_transcript.missing_signatures(),
        [2].into_iter().collect()
    );
    frost_transcript.contribute(&joint_key, 2, &ss3, &mps3)?;

    let mut psbt = frost_transcript.finish(&joint_key)?;

    wallet
        .finalize_psbt(&mut psbt, SignOptions::default())
        .unwrap();
    let tx = psbt.extract_tx();
    let txid = tx.txid();
    Broadcast::broadcast(wallet.client(), tx).unwrap();

    wallet.sync(noop_progress(), None).unwrap();

    assert!(wallet.get_tx(&txid, false)?.is_some());

    Ok(())
}
