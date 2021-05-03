use anyhow::Context;
use bdk::{
    bitcoin::Network,
    blockchain::{
        esplora::EsploraBlockchainConfig, noop_progress, AnyBlockchainConfig, Blockchain,
        EsploraBlockchain,
    },
    database::BatchDatabase,
    wallet::AddressIndex,
    Wallet,
};
use bet_database::BetState;
use bweet::{
    bet_database,
    bitcoin::Amount,
    keychain::Keychain,
    party::{Party},
};
use olivia_core::{Event, EventId, Group, OracleEvent, OracleInfo, OracleKeys, Attestation};
use olivia_secp256k1::{Secp256k1};
use std::{str::FromStr, time::Duration};

async fn create_party(id: u8) -> anyhow::Result<Party<impl Blockchain, impl BatchDatabase>> {
    let keychain = Keychain::new([id; 64]);
    let descriptor = bdk::template::Bip84(
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

    let bet_db = bet_database::BetDatabase::test_new();

    while wallet.get_balance()? < 100_000 {
        fund_wallet(&wallet).await?;
        tokio::time::sleep(Duration::from_millis(1_000)).await;
        wallet.sync(noop_progress(), None).await?;
        println!("syncing done on party {} -- checking balance", id);
    }

    let party = Party::new(
        wallet,
        bet_db,
        keychain,
        AnyBlockchainConfig::Esplora(EsploraBlockchainConfig {
            base_url: esplora_url,
            concurrency: None,
        }),
    );
    Ok(party)
}

async fn fund_wallet(wallet: &Wallet<impl Blockchain, impl BatchDatabase>) -> anyhow::Result<()> {
    let new_address = wallet.get_address(AddressIndex::New)?;
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
    use olivia_secp256k1::fun::s;
    let party_1 = create_party(1).await.unwrap();
    let party_2 = create_party(2).await.unwrap();
    let nonce_secret_key = s!(7);
    let announce_keypair = olivia_secp256k1::SCHNORR.new_keypair(s!(8));
    let attest_keypair = olivia_secp256k1::SCHNORR.new_keypair(s!(10));
    let oracle_nonce_keypair = olivia_secp256k1::SCHNORR.new_keypair(nonce_secret_key);
    let event_id = EventId::from_str("/test/red_blue?left-win").unwrap();
    let oracle_id = "oracle.com".to_string();
    let oracle_info = OracleInfo {
        id: oracle_id.clone(),
        oracle_keys: OracleKeys {
            attestation_key: attest_keypair.public_key().clone().into(),
            announcement_key: announce_keypair.public_key().clone().into(),
        },
    };

    party_1.trust_oracle(oracle_info.clone()).unwrap();
    party_2.trust_oracle(oracle_info.clone()).unwrap();

    let oracle_event = OracleEvent::<Secp256k1> {
        event: Event {
            id: event_id.clone(),
            expected_outcome_time: None,
        },
        nonces: vec![oracle_nonce_keypair.public_key().clone().into()],
    };

    let (p1_bet_id, proposal) = party_1
        .make_proposal(
            oracle_id.clone(),
            oracle_event.clone(),
            Amount::from_str_with_denomination("0.01 BTC").unwrap(),
        )
        .unwrap();

    let (p2_bet_id, encrypted_offer) = {
        let (bet, offer, cipher) = party_2
            .generate_offer_with_oracle_event(
                proposal.clone(),
                true,
                Amount::from_str_with_denomination("0.02 BTC").unwrap(),
                oracle_event,
                oracle_info,
            )
            .await
            .unwrap();
        party_2.save_and_encrypt_offer(bet, offer, cipher).unwrap()
    };

    let validated_offer = party_1.decrypt_and_validate_offer(p1_bet_id, encrypted_offer).await.unwrap();

    party_1
        .take_offer(validated_offer)
        .unwrap();

    while party_1
        .bet_db()
        .get_entity::<BetState>(p1_bet_id)
        .unwrap()
        .unwrap()
        .name()
        != "confirmed"
    {
        party_1.take_next_action(p1_bet_id).await.unwrap();
    }
    while party_2
        .bet_db()
        .get_entity::<BetState>(p2_bet_id)
        .unwrap()
        .unwrap()
        .name()
        != "confirmed"
    {
        party_2.take_next_action(p2_bet_id).await.unwrap();
    }

    party_1.bet_db().get_entity::<BetState>(p1_bet_id).unwrap();
    party_2.bet_db().get_entity::<BetState>(p2_bet_id).unwrap();

    let (outcome, index, winner, winner_id, loser, loser_id) = match rand::random() {
        false => ("red_win", 0, &party_1, p1_bet_id, party_2, p2_bet_id),
        true  => ("blue_win", 1, &party_2, p2_bet_id, party_1, p1_bet_id),
    };


    let winner_initial_balance = winner.wallet().get_balance().unwrap();

    let attestation =
        Attestation {
            outcome: outcome.into(),
            scalars: vec![Secp256k1::reveal_attest_scalar(&attest_keypair, oracle_nonce_keypair.into(), index).into()],
            time: olivia_core::chrono::Utc::now().naive_utc(),
        };

    winner
        .learn_outcome(winner_id, attestation.clone())
        .unwrap();
   loser.learn_outcome(loser_id, attestation).unwrap();

    let winner_claim = winner
        .claim_to(None)
        .unwrap()
        .expect("winner should return a tx here");
    assert!(
        loser.claim_to(None).unwrap().is_none(),
        "loser should not have claim tx"
    );

    assert_eq!(winner_claim.bets, vec![winner_id]);
    winner.wallet().broadcast(winner_claim.tx).await.unwrap();
    winner.wallet().sync(noop_progress(), None).await.unwrap();

    assert!(winner.wallet().get_balance().unwrap() > winner_initial_balance);
}
