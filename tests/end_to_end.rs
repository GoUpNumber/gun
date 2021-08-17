use anyhow::Context;
use bdk::{
    bitcoin::Network,
    blockchain::{
        esplora::{EsploraBlockchainConfig, EsploraKind},
        noop_progress, AnyBlockchainConfig, Broadcast, EsploraBlockchain,
    },
    database::BatchDatabase,
    testutils::blockchain_tests::TestClient,
    wallet::AddressIndex,
    FeeRate, Wallet,
};
use bet_database::BetState;
use gun_wallet::{
    bet_database,
    bitcoin::Amount,
    keychain::Keychain,
    party::{BetArgs, Party},
    FeeSpec, ValueChoice,
};
use olivia_core::{
    announce, attest, AnnouncementSchemes, Attestation, AttestationSchemes, Event, EventId, Group,
    OracleEvent, OracleInfo, OracleKeys,
};
use olivia_secp256k1::{fun::Scalar, Secp256k1};
use rand::Rng;
use std::{str::FromStr, time::Duration};

fn create_party(
    test_client: &mut TestClient,
    id: u8,
) -> anyhow::Result<Party<EsploraBlockchain, impl BatchDatabase>> {
    let mut r = [0u8; 64];
    rand::thread_rng().fill(&mut r);
    let keychain = Keychain::new(r);
    let descriptor = bdk::template::Bip84(
        keychain.main_wallet_xprv(Network::Regtest),
        bdk::KeychainKind::External,
    );
    let db = bdk::database::MemoryDatabase::new();
    let esplora_url = format!(
        "http://{}",
        test_client.electrsd.esplora_url.as_ref().unwrap()
    );
    let esplora = EsploraBlockchain::new(&esplora_url, None, 5);

    let wallet = Wallet::new(descriptor, None, Network::Regtest, db, esplora)
        .context("Initializing wallet failed")?;
    wallet
        .sync(noop_progress(), None)
        .context("syncing wallet failed")?;

    let bet_db = bet_database::BetDatabase::test_new();

    let funding_address = wallet.get_address(AddressIndex::New).unwrap().address;

    test_client.generate(1, Some(funding_address));
    test_client.generate(100, None);

    while wallet.get_balance()? < 100_000 {
        std::thread::sleep(Duration::from_millis(1_000));
        wallet.sync(noop_progress(), None)?;
        println!("syncing done on party {} -- checking balance", id);
    }

    let party = Party::new(
        wallet,
        bet_db,
        keychain,
        AnyBlockchainConfig::Esplora(EsploraBlockchainConfig {
            base_url: esplora_url,
            concurrency: None,
            stop_gap: 5,
            kind: EsploraKind::Esplora,
        }),
    );
    Ok(party)
}

macro_rules! setup_test {
    () => {{
        let mut test_client = TestClient::default();
        let party_1 = create_party(&mut test_client, 1).unwrap();
        let party_2 = create_party(&mut test_client, 2).unwrap();
        let nonce_secret_key = Scalar::random(&mut rand::thread_rng());
        let announce_keypair =
            olivia_secp256k1::SCHNORR.new_keypair(Scalar::random(&mut rand::thread_rng()));
        let attest_keypair =
            olivia_secp256k1::SCHNORR.new_keypair(Scalar::random(&mut rand::thread_rng()));
        let oracle_nonce_keypair = olivia_secp256k1::SCHNORR.new_keypair(nonce_secret_key);
        let event_id = EventId::from_str("/test/red_blue.winner").unwrap();
        let oracle_id = "non-existent-oracle.com".to_string();
        let oracle_info = OracleInfo {
            id: oracle_id.clone(),
            oracle_keys: OracleKeys {
                olivia_v1: Some(attest_keypair.public_key().clone().into()),
                ecdsa_v1: None,
                announcement: announce_keypair.public_key().clone().into(),
                group: Secp256k1,
            },
        };

        party_1.trust_oracle(oracle_info.clone()).unwrap();
        party_2.trust_oracle(oracle_info.clone()).unwrap();

        let oracle_event = OracleEvent::<Secp256k1> {
            event: Event {
                id: event_id.clone(),
                expected_outcome_time: None,
            },
            schemes: AnnouncementSchemes {
                olivia_v1: Some(announce::OliviaV1 {
                    nonces: vec![oracle_nonce_keypair.public_key().clone().into()],
                }),
                ..Default::default()
            },
        };
        (
            test_client,
            party_1,
            party_2,
            oracle_info,
            attest_keypair,
            oracle_nonce_keypair,
            oracle_id,
            oracle_event,
        )
    }};
}

macro_rules! wait_for_state {
    ($party:ident, $bet_id:ident, $state:literal) => {{
        let mut counter: usize = 0;
        let mut cur_state: String;
        while {
            cur_state = $party
                .bet_db()
                .get_entity::<BetState>($bet_id)
                .unwrap()
                .unwrap()
                .name()
                .into();
            cur_state != $state
        } {
            $party.take_next_action($bet_id, false).unwrap();
            counter += 1;
            std::thread::sleep(std::time::Duration::from_secs(1));
            if counter > 10 {
                panic!(
                    "{}/{} has failed to reach state {}. It ended up in {}",
                    stringify!($party),
                    stringify!($bet_id),
                    $state,
                    cur_state
                );
            }
        }
    }};
}

#[test]
pub fn test_happy_path() {
    let (
        mut test_client,
        party_1,
        party_2,
        oracle_info,
        attest_keypair,
        oracle_nonce_keypair,
        oracle_id,
        oracle_event,
    ) = setup_test!();

    let (p1_bet_id, proposal) = party_1
        .make_proposal(
            oracle_id.clone(),
            oracle_event.clone(),
            BetArgs {
                value: ValueChoice::Amount(Amount::from_str_with_denomination("0.01 BTC").unwrap()),
                ..Default::default()
            },
        )
        .unwrap();

    let (p2_bet_id, encrypted_offer) = {
        let (bet, offer, local_public_key, mut cipher) = party_2
            .generate_offer_with_oracle_event(
                proposal.clone(),
                true,
                oracle_event,
                oracle_info,
                BetArgs {
                    value: ValueChoice::Amount(
                        Amount::from_str_with_denomination("0.02 BTC").unwrap(),
                    ),
                    ..Default::default()
                },
                FeeSpec::default(),
            )
            .unwrap();
        party_2
            .save_and_encrypt_offer(bet, offer, None, local_public_key, &mut cipher)
            .unwrap()
    };
    wait_for_state!(party_2, p2_bet_id, "offered");

    let (decrypted_offer, offer_public_key, rng) =
        party_1.decrypt_offer(p1_bet_id, encrypted_offer).unwrap();
    let validated_offer = party_1
        .validate_offer(
            p1_bet_id,
            decrypted_offer.into_offer(),
            offer_public_key,
            rng,
        )
        .unwrap();

    Broadcast::broadcast(
        party_1.wallet().client(),
        validated_offer.bet.psbt.clone().extract_tx(),
    )
    .unwrap();
    party_1.set_offer_taken(validated_offer).unwrap();
    wait_for_state!(party_1, p1_bet_id, "unconfirmed");
    test_client.generate(1, None);

    wait_for_state!(party_1, p1_bet_id, "confirmed");
    wait_for_state!(party_2, p2_bet_id, "confirmed");

    let (outcome, index, winner, winner_id, loser, loser_id) = match rand::random() {
        false => ("red", 0, &party_1, p1_bet_id, party_2, p2_bet_id),
        true => ("blue", 1, &party_2, p2_bet_id, party_1, p1_bet_id),
    };

    let winner_initial_balance = winner.wallet().get_balance().unwrap();

    let attestation = Attestation {
        outcome: outcome.into(),
        schemes: AttestationSchemes {
            olivia_v1: Some(attest::OliviaV1 {
                scalars: vec![Secp256k1::reveal_attest_scalar(
                    &attest_keypair,
                    oracle_nonce_keypair.into(),
                    index,
                )
                .into()],
            }),
            ..Default::default()
        },
        time: olivia_core::chrono::Utc::now().naive_utc(),
    };

    winner
        .learn_outcome(winner_id, attestation.clone())
        .unwrap();
    wait_for_state!(winner, winner_id, "won");

    loser.learn_outcome(loser_id, attestation).unwrap();
    assert!(
        loser.claim(FeeSpec::default(), false).unwrap().is_none(),
        "loser should not have claim tx"
    );
    wait_for_state!(loser, loser_id, "lost");

    let (bet_ids_claimed, winner_claim_psbt) = winner
        .claim(FeeSpec::default(), false)
        .unwrap()
        .expect("winner should return a tx here");

    let winner_claim_tx = winner_claim_psbt.extract_tx();
    winner
        .set_bets_to_claiming(&bet_ids_claimed, winner_claim_tx.txid())
        .unwrap();

    wait_for_state!(winner, winner_id, "claiming");

    winner.wallet().broadcast(winner_claim_tx).unwrap();
    test_client.generate(1, None);
    winner.wallet().sync(noop_progress(), None).unwrap();

    assert!(winner.wallet().get_balance().unwrap() > winner_initial_balance);
    wait_for_state!(winner, winner_id, "claimed");
}

#[test]
pub fn cancel_proposal() {
    let (mut test_client, party_1, party_2, oracle_info, _, _, oracle_id, oracle_event) =
        setup_test!();

    let (p1_bet_id, proposal) = party_1
        .make_proposal(
            oracle_id.clone(),
            oracle_event.clone(),
            BetArgs {
                value: ValueChoice::Amount(Amount::from_str_with_denomination("0.02 BTC").unwrap()),
                ..Default::default()
            },
        )
        .unwrap();

    let (bet_id_overlap, _tmp) = party_1
        .make_proposal(
            oracle_id.clone(),
            oracle_event.clone(),
            BetArgs {
                value: ValueChoice::Amount(Amount::from_str_with_denomination("0.01 BTC").unwrap()),
                must_overlap: &[p1_bet_id],
                ..Default::default()
            },
        )
        .unwrap();

    let (p2_bet_id, _) = {
        let (bet, offer, offer_public_key, mut cipher) = party_2
            .generate_offer_with_oracle_event(
                proposal.clone(),
                true,
                oracle_event,
                oracle_info,
                BetArgs {
                    value: ValueChoice::Amount(
                        Amount::from_str_with_denomination("0.02 BTC").unwrap(),
                    ),
                    ..Default::default()
                },
                FeeSpec::default(),
            )
            .unwrap();
        party_2
            .save_and_encrypt_offer(bet, offer, None, offer_public_key, &mut cipher)
            .unwrap()
    };

    let psbt = party_1
        .generate_cancel_tx(&[p1_bet_id], FeeSpec::default())
        .unwrap()
        .expect("should be able to cancel");
    let tx = psbt.extract_tx();
    party_1
        .set_bets_to_cancelling(&[p1_bet_id], tx.txid())
        .unwrap();
    Broadcast::broadcast(party_1.wallet().client(), tx).unwrap();
    wait_for_state!(party_1, p1_bet_id, "cancelling");
    test_client.generate(1, None);
    wait_for_state!(party_1, bet_id_overlap, "cancelled");
    wait_for_state!(party_1, p1_bet_id, "cancelled");
    wait_for_state!(party_2, p2_bet_id, "cancelled");
}

#[test]
pub fn test_cancel_offer() {
    let (mut test_client, party_1, party_2, oracle_info, _, _, oracle_id, oracle_event) =
        setup_test!();

    let (_, proposal) = party_1
        .make_proposal(
            oracle_id.clone(),
            oracle_event.clone(),
            BetArgs {
                value: ValueChoice::Amount(Amount::from_str_with_denomination("0.01 BTC").unwrap()),
                ..Default::default()
            },
        )
        .unwrap();

    let (p2_bet_id, _) = {
        let (bet, offer, offer_public_key, mut cipher) = party_2
            .generate_offer_with_oracle_event(
                proposal.clone(),
                true,
                oracle_event,
                oracle_info,
                BetArgs {
                    value: ValueChoice::Amount(
                        Amount::from_str_with_denomination("0.02 BTC").unwrap(),
                    ),
                    ..Default::default()
                },
                FeeSpec::default(),
            )
            .unwrap();
        party_2
            .save_and_encrypt_offer(bet, offer, None, offer_public_key, &mut cipher)
            .unwrap()
    };

    let psbt = party_2
        .generate_cancel_tx(&[p2_bet_id], FeeSpec::default())
        .unwrap()
        .expect("should be able to cancel");
    let tx = psbt.extract_tx();
    party_2
        .set_bets_to_cancelling(&[p2_bet_id], tx.txid())
        .unwrap();
    Broadcast::broadcast(party_2.wallet().client(), tx).unwrap();

    wait_for_state!(party_2, p2_bet_id, "cancelling");
    test_client.generate(1, None);
    wait_for_state!(party_2, p2_bet_id, "cancelled");
}

#[test]
pub fn cancel_offer_after_offer_taken() {
    let (mut test_client, party_1, party_2, oracle_info, _, _, oracle_id, oracle_event) =
        setup_test!();

    let (p1_bet_id, proposal) = party_1
        .make_proposal(
            oracle_id.clone(),
            oracle_event.clone(),
            BetArgs {
                value: ValueChoice::Amount(Amount::from_str_with_denomination("0.01 BTC").unwrap()),
                ..Default::default()
            },
        )
        .unwrap();

    let (first_p2_bet_id, _) = {
        let (bet, offer, offer_public_key, mut cipher) = party_2
            .generate_offer_with_oracle_event(
                proposal.clone(),
                true,
                oracle_event.clone(),
                oracle_info.clone(),
                BetArgs {
                    value: ValueChoice::Amount(
                        Amount::from_str_with_denomination("0.02 BTC").unwrap(),
                    ),
                    ..Default::default()
                },
                FeeSpec::default(),
            )
            .unwrap();
        party_2
            .save_and_encrypt_offer(bet, offer, None, offer_public_key, &mut cipher)
            .unwrap()
    };

    let (second_p2_bet_id, second_encrypted_offer) = {
        let (bet, offer, offer_public_key, mut cipher) = party_2
            .generate_offer_with_oracle_event(
                proposal.clone(),
                true,
                oracle_event,
                oracle_info,
                BetArgs {
                    value: ValueChoice::Amount(
                        Amount::from_str_with_denomination("0.03 BTC").unwrap(),
                    ),
                    must_overlap: &[first_p2_bet_id],
                    ..Default::default()
                },
                FeeSpec::Rate(FeeRate::from_sat_per_vb(1.0)),
            )
            .unwrap();
        party_2
            .save_and_encrypt_offer(bet, offer, None, offer_public_key, &mut cipher)
            .unwrap()
    };

    let (second_decrypted_offer, second_offer_public_key, rng) = party_1
        .decrypt_offer(p1_bet_id, second_encrypted_offer)
        .unwrap();
    let second_validated_offer = party_1
        .validate_offer(
            p1_bet_id,
            second_decrypted_offer.into_offer(),
            second_offer_public_key,
            rng,
        )
        .unwrap();

    Broadcast::broadcast(party_1.wallet().client(), second_validated_offer.tx()).unwrap();
    party_1.set_offer_taken(second_validated_offer).unwrap();

    wait_for_state!(party_1, p1_bet_id, "unconfirmed");
    let psbt = party_2
        .generate_cancel_tx(
            &[first_p2_bet_id, second_p2_bet_id],
            FeeSpec::Rate(FeeRate::from_sat_per_vb(5.0)),
        )
        .unwrap()
        .expect("should be able to cancel");
    let tx = psbt.extract_tx();
    party_2
        .set_bets_to_cancelling(&[first_p2_bet_id, second_p2_bet_id], tx.txid())
        .unwrap();
    Broadcast::broadcast(party_2.wallet().client(), tx).unwrap();

    wait_for_state!(party_2, second_p2_bet_id, "cancelling");
    wait_for_state!(party_2, first_p2_bet_id, "cancelling");
    test_client.generate(1, None);
    wait_for_state!(party_2, second_p2_bet_id, "cancelled");
    wait_for_state!(party_2, first_p2_bet_id, "cancelled");
}
