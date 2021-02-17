use anyhow::Context;
use bdk::{
    bitcoin::Network,
    blockchain::{noop_progress, Blockchain, EsploraBlockchain},
    database::BatchDatabase,
    Wallet,
};
use bweet::{
    bet_database,
    bitcoin::Amount,
    keychain::Keychain,
    party::{Party, TxTracker},
};
use olivia_core::{Event, EventId, OracleEvent, OracleInfo, Schnorr};
use olivia_secp256k1::{fun::Scalar, Secp256k1};
use std::{str::FromStr, time::Duration};

async fn create_party(
    id: u8,
) -> anyhow::Result<Party<impl Blockchain, impl BatchDatabase, impl bet_database::BetDatabase>> {
    let keychain = Keychain::new([id; 64]);
    let descriptor = bdk::template::BIP84(
        keychain.main_wallet_xprv(Network::Regtest),
        bdk::KeychainKind::External,
    );
    let db = bdk::database::MemoryDatabase::new();
    let esplora_url = "http://localhost:3000".to_string();
    let esplora = EsploraBlockchain::new(&esplora_url, None);
    let wallet = Wallet::new(descriptor, None, Network::Regtest, db, esplora)
        .await
        .context("Initializing wallet failed")?;
    wallet
        .sync(noop_progress(), None)
        .await
        .context("syncing wallet failed")?;

    let bet_db = bet_database::InMemory::default();

    while wallet.get_balance()? < 100_000 {
        fund_wallet(&wallet).await?;
        tokio::time::sleep(Duration::from_millis(1_000)).await;
        wallet.sync(noop_progress(), None).await?;
        println!("syncing done on party {} -- checking balance", id);
    }

    let party = Party::new(wallet, bet_db, keychain, esplora_url);
    Ok(party)
}

async fn fund_wallet(wallet: &Wallet<impl Blockchain, impl BatchDatabase>) -> anyhow::Result<()> {
    let new_address = wallet.get_new_address()?;
    println!("funding: {}", new_address);
    bweet::reqwest::Client::new()
        .post("http://localhost:3000/faucet")
        .json(&serde_json::json!({ "address": new_address }))
        .send()
        .await?;
    Ok(())
}

#[tokio::test]
pub async fn end_to_end() {
    let party_1 = create_party(1).await.unwrap();
    let p1_initial_balance = party_1.wallet().get_balance().unwrap();
    let party_2 = create_party(2).await.unwrap();
    let secret_key = Scalar::random(&mut rand::thread_rng());
    let nonce_secret_key = Scalar::random(&mut rand::thread_rng());
    let oracle_keypair = olivia_secp256k1::SCHNORR.new_keypair(secret_key);
    let oracle_nonce_keypair = olivia_secp256k1::SCHNORR.new_keypair(nonce_secret_key);
    let event_id = EventId::from_str("/test/red_blue?left-win").unwrap();
    let oracle_id = "oracle.com".to_string();
    let oracle_info = OracleInfo {
        id: oracle_id,
        public_key: oracle_keypair.public_key().clone().into(),
    };

    let oracle_event = OracleEvent::<Secp256k1> {
        event: Event {
            id: event_id.clone(),
            expected_outcome_time: None,
        },
        nonces: vec![oracle_nonce_keypair.public_key().clone().into()],
    };

    let (p1_bet_id, proposal) = party_1
        .make_proposal(
            oracle_info.clone(),
            oracle_event.clone(),
            Amount::from_str_with_denomination("0.01 BTC").unwrap(),
        )
        .unwrap();

    let (p2_bet_id, encrypted_offer, joint_output_2, txid_2) = party_2
        .make_offer_with_oracle_event(
            proposal.clone(),
            true,
            Amount::from_str_with_denomination("0.02 BTC").unwrap(),
            oracle_event,
            oracle_info,
        )
        .await
        .unwrap();

    let (local_proposal, decrypted_offer) =
        party_1.decrypt_offer(p1_bet_id, encrypted_offer).unwrap();

    let offer_inputs = party_1.lookup_offer_inputs(&decrypted_offer.offer).await.unwrap();

    let joint_output_1 = party_1
        .take_offer(p1_bet_id, local_proposal, decrypted_offer, offer_inputs)
        .await
        .unwrap();

    assert_eq!(joint_output_1.descriptor(), joint_output_2.descriptor());
    let tracker = TxTracker::new(
        txid_2,
        joint_output_2.wallet_descriptor(),
        EsploraBlockchain::new("http://localhost:3000", None),
        party_2.wallet().network(),
    )
    .await
    .unwrap();

    let tx_details = tracker.wait_confirmed().await.unwrap();

    party_1
        .bet_confirmed(p1_bet_id, tx_details.height.unwrap())
        .unwrap();
    party_2
        .bet_confirmed(p2_bet_id, tx_details.height.unwrap())
        .unwrap();

    let outcome = event_id.fragments(0).nth(0).unwrap();
    let attestation: Scalar<_, _> = Secp256k1::reveal_signature_s(
        &oracle_keypair,
        oracle_nonce_keypair.into(),
        outcome.to_string().as_bytes(),
    )
    .into();

    party_1.claim(p1_bet_id, attestation).await.unwrap();
    party_1.wallet().sync(noop_progress(), None).await.unwrap();
    assert!(party_1.wallet().get_balance().unwrap() > p1_initial_balance);
}
