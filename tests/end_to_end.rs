use anyhow::Context;
use bdk::{
    bitcoin::{util::bip32::ExtendedPrivKey, Amount, Network},
    blockchain::{noop_progress, Broadcast, EsploraBlockchain},
    testutils::blockchain_tests::TestClient,
    wallet::AddressIndex,
    FeeRate, Wallet,
};
use gun_wallet::{
    betting::*, database::GunDatabase, keychain::Keychain, wallet::GunWallet, FeeSpec, ValueChoice,
};
use olivia_core::{
    announce, attest, AnnouncementSchemes, Attestation, AttestationSchemes, Event, EventId, Group,
    OracleEvent, OracleInfo, OracleKeys,
};
use olivia_secp256k1::{fun::Scalar, Secp256k1};
use rand::Rng;
use std::{str::FromStr, time::Duration};

fn create_party(test_client: &mut TestClient, id: u8) -> anyhow::Result<(GunWallet, Keychain)> {
    let mut r = [0u8; 64];
    rand::thread_rng().fill(&mut r);
    let keychain = Keychain::new(r);
    let xprv = ExtendedPrivKey::new_master(Network::Regtest, &r).unwrap();
    let descriptor = bdk::template::Bip84(xprv, bdk::KeychainKind::External);
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

    let wallet = Wallet::new(descriptor, None, Network::Regtest, db, esplora)
        .context("Initializing wallet failed")?;
    wallet
        .sync(noop_progress(), None)
        .context("syncing wallet failed")?;

    let gun_db = GunDatabase::test_new();

    let funding_address = wallet.get_address(AddressIndex::New).unwrap().address;

    test_client.generate(1, Some(funding_address));
    test_client.generate(100, None);

    while wallet.get_balance()? < 100_000 {
        std::thread::sleep(Duration::from_millis(1_000));
        wallet.sync(noop_progress(), None)?;
        println!("syncing done on party {} -- checking balance", id);
    }

    let wallet = GunWallet::new(wallet, gun_db);
    Ok((wallet, keychain))
}

macro_rules! setup_test {
    () => {{
        let mut test_client = TestClient::default();
        let (party_1, keychain_1) = create_party(&mut test_client, 1).unwrap();
        let (party_2, keychain_2) = create_party(&mut test_client, 2).unwrap();
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

        let oracle_event = OracleEvent {
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
            (party_1, keychain_1),
            (party_2, keychain_2),
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
        let mut cur_state;
        while {
            cur_state = $party
                .gun_db()
                .get_entity::<BetState>($bet_id)
                .unwrap()
                .unwrap();
            cur_state.name() != $state
        } {
            $party.take_next_action($bet_id, false).unwrap();
            counter += 1;
            std::thread::sleep(std::time::Duration::from_secs(1));
            if counter > 10 {
                panic!(
                    "{}/{} has failed to reach state {}. It ended up in {}. {:?}",
                    stringify!($party),
                    stringify!($bet_id),
                    $state,
                    cur_state.name(),
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
        (party_1, keychain_1),
        (party_2, keychain_2),
        oracle_info,
        attest_keypair,
        oracle_nonce_keypair,
        oracle_id,
        oracle_event,
    ) = setup_test!();

    let local_proposal = party_1
        .make_proposal(
            oracle_id.clone(),
            oracle_event.clone(),
            BetArgs {
                value: ValueChoice::Amount(Amount::from_str_with_denomination("0.01 BTC").unwrap()),
                ..Default::default()
            },
            &keychain_1,
        )
        .unwrap();

    let proposal_string = local_proposal.proposal.clone().into_versioned().to_string();
    let p1_bet_id = party_1
        .gun_db()
        .insert_bet(BetState::Proposed { local_proposal })
        .unwrap();

    let (p2_bet_id, encrypted_offer, _) = {
        let proposal = VersionedProposal::from_str(&proposal_string).unwrap();
        let (bet, local_public_key, mut cipher) = party_2
            .generate_offer_with_oracle_event(
                proposal.into(),
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
                &keychain_2,
            )
            .unwrap();
        party_2
            .sign_save_and_encrypt_offer(bet, None, local_public_key, &mut cipher)
            .unwrap()
    };
    wait_for_state!(party_2, p2_bet_id, "offered");

    let (decrypted_offer, offer_public_key, rng) = party_1
        .decrypt_offer(p1_bet_id, encrypted_offer, &keychain_1)
        .unwrap();
    let mut validated_offer = party_1
        .validate_offer(
            p1_bet_id,
            decrypted_offer.into_offer(),
            offer_public_key,
            rng,
            &keychain_1,
        )
        .unwrap();
    party_1.sign_validated_offer(&mut validated_offer).unwrap();

    Broadcast::broadcast(
        party_1.bdk_wallet().client(),
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

    let winner_initial_balance = winner.bdk_wallet().get_balance().unwrap();

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

    let (_, winner_claim_psbt) = winner
        .claim(FeeSpec::default(), false)
        .unwrap()
        .expect("winner should return a tx here");

    let winner_claim_tx = winner_claim_psbt.extract_tx();

    winner.bdk_wallet().broadcast(&winner_claim_tx).unwrap();
    wait_for_state!(winner, winner_id, "claiming");
    test_client.generate(1, None);
    wait_for_state!(winner, winner_id, "claimed");
    winner.bdk_wallet().sync(noop_progress(), None).unwrap();

    assert!(winner.bdk_wallet().get_balance().unwrap() > winner_initial_balance);
    wait_for_state!(winner, winner_id, "claimed");
}

#[test]
pub fn cancel_proposal() {
    let (
        mut test_client,
        (party_1, keychain_1),
        (party_2, keychain_2),
        oracle_info,
        _,
        _,
        oracle_id,
        oracle_event,
    ) = setup_test!();

    let local_proposal_1 = party_1
        .make_proposal(
            oracle_id.clone(),
            oracle_event.clone(),
            BetArgs {
                value: ValueChoice::Amount(Amount::from_str_with_denomination("0.02 BTC").unwrap()),
                ..Default::default()
            },
            &keychain_1,
        )
        .unwrap();

    let proposal_1 = local_proposal_1
        .proposal
        .clone()
        .into_versioned()
        .to_string();

    let p1_bet_id = party_1
        .gun_db()
        .insert_bet(BetState::Proposed {
            local_proposal: local_proposal_1,
        })
        .unwrap();

    let local_proposal_2 = party_1
        .make_proposal(
            oracle_id.clone(),
            oracle_event.clone(),
            BetArgs {
                value: ValueChoice::Amount(Amount::from_str_with_denomination("0.01 BTC").unwrap()),
                must_overlap: &[p1_bet_id],
                ..Default::default()
            },
            &keychain_2,
        )
        .unwrap();

    let bet_id_overlap = party_1
        .gun_db()
        .insert_bet(BetState::Proposed {
            local_proposal: local_proposal_2,
        })
        .unwrap();

    let (p2_bet_id, _, _) = {
        let proposal = VersionedProposal::from_str(&proposal_1).unwrap();
        let (bet, offer_public_key, mut cipher) = party_2
            .generate_offer_with_oracle_event(
                proposal.into(),
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
                &keychain_2,
            )
            .unwrap();
        party_2
            .sign_save_and_encrypt_offer(bet, None, offer_public_key, &mut cipher)
            .unwrap()
    };

    let psbt = party_1
        .generate_cancel_tx(&[p1_bet_id], FeeSpec::default())
        .unwrap()
        .expect("should be able to cancel");
    let tx = psbt.extract_tx();
    Broadcast::broadcast(party_1.bdk_wallet().client(), tx).unwrap();
    wait_for_state!(party_1, p1_bet_id, "canceling");
    test_client.generate(1, None);
    wait_for_state!(party_1, bet_id_overlap, "canceled");
    //     wait_for_state!(party_1, p1_bet_id, "canceled");
    wait_for_state!(party_2, p2_bet_id, "canceled");
}

#[test]
pub fn test_cancel_offer() {
    let (
        mut test_client,
        (party_1, keychain_1),
        (party_2, keychain_2),
        oracle_info,
        _,
        _,
        oracle_id,
        oracle_event,
    ) = setup_test!();

    let local_proposal = party_1
        .make_proposal(
            oracle_id.clone(),
            oracle_event.clone(),
            BetArgs {
                value: ValueChoice::Amount(Amount::from_str_with_denomination("0.01 BTC").unwrap()),
                ..Default::default()
            },
            &keychain_1,
        )
        .unwrap();

    let proposal_str = local_proposal.proposal.clone().into_versioned().to_string();

    let (p2_bet_id, _, _) = {
        let proposal = VersionedProposal::from_str(&proposal_str).unwrap();
        let (bet, offer_public_key, mut cipher) = party_2
            .generate_offer_with_oracle_event(
                proposal.into(),
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
                &keychain_2,
            )
            .unwrap();
        party_2
            .sign_save_and_encrypt_offer(bet, None, offer_public_key, &mut cipher)
            .unwrap()
    };

    let psbt = party_2
        .generate_cancel_tx(&[p2_bet_id], FeeSpec::default())
        .unwrap()
        .expect("should be able to cancel");
    let tx = psbt.extract_tx();
    Broadcast::broadcast(party_2.bdk_wallet().client(), tx).unwrap();

    wait_for_state!(party_2, p2_bet_id, "canceling");
    test_client.generate(1, None);
    wait_for_state!(party_2, p2_bet_id, "canceled");
}

#[test]
pub fn cancel_offer_after_offer_taken() {
    let (
        mut test_client,
        (party_1, keychain_1),
        (party_2, keychain_2),
        oracle_info,
        _,
        _,
        oracle_id,
        oracle_event,
    ) = setup_test!();

    let local_proposal = party_1
        .make_proposal(
            oracle_id.clone(),
            oracle_event.clone(),
            BetArgs {
                value: ValueChoice::Amount(Amount::from_str_with_denomination("0.01 BTC").unwrap()),
                ..Default::default()
            },
            &keychain_1,
        )
        .unwrap();

    let proposal_str = local_proposal.proposal.clone().into_versioned().to_string();
    let p1_bet_id = party_1
        .gun_db()
        .insert_bet(BetState::Proposed { local_proposal })
        .unwrap();
    let proposal = Proposal::from(VersionedProposal::from_str(&proposal_str).unwrap());

    let (first_p2_bet_id, _, _) = {
        let (bet, offer_public_key, mut cipher) = party_2
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
                &keychain_2,
            )
            .unwrap();
        party_2
            .sign_save_and_encrypt_offer(bet, None, offer_public_key, &mut cipher)
            .unwrap()
    };

    let (second_p2_bet_id, second_encrypted_offer, _) = {
        let (bet, offer_public_key, mut cipher) = party_2
            .generate_offer_with_oracle_event(
                proposal,
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
                &keychain_2,
            )
            .unwrap();
        party_2
            .sign_save_and_encrypt_offer(bet, None, offer_public_key, &mut cipher)
            .unwrap()
    };

    let (second_decrypted_offer, second_offer_public_key, rng) = party_1
        .decrypt_offer(p1_bet_id, second_encrypted_offer, &keychain_1)
        .unwrap();
    let mut second_validated_offer = party_1
        .validate_offer(
            p1_bet_id,
            second_decrypted_offer.into_offer(),
            second_offer_public_key,
            rng,
            &keychain_1,
        )
        .unwrap();
    party_1
        .sign_validated_offer(&mut second_validated_offer)
        .unwrap();

    Broadcast::broadcast(party_1.bdk_wallet().client(), second_validated_offer.tx()).unwrap();
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
    Broadcast::broadcast(party_2.bdk_wallet().client(), tx).unwrap();

    wait_for_state!(party_2, second_p2_bet_id, "canceling");
    wait_for_state!(party_2, first_p2_bet_id, "canceling");
    test_client.generate(1, None);
    wait_for_state!(party_2, second_p2_bet_id, "canceled");
    wait_for_state!(party_2, first_p2_bet_id, "canceled");
}

#[test]
fn create_proposal_with_dust_change() {
    let (
        mut test_client,
        (party_1, keychain_1),
        (party_2, keychain_2),
        oracle_info,
        _,
        _,
        oracle_id,
        oracle_event,
    ) = setup_test!();

    let balance = party_1.bdk_wallet().get_balance().unwrap();
    let bet_value = balance - 250;

    let local_proposal = party_1
        .make_proposal(
            oracle_id.clone(),
            oracle_event.clone(),
            BetArgs {
                value: ValueChoice::Amount(Amount::from_sat(bet_value)),
                ..Default::default()
            },
            &keychain_1,
        )
        .unwrap();

    assert_eq!(local_proposal.change, None);
    assert_eq!(local_proposal.proposal.value.as_sat(), bet_value);

    let p1_bet_id = party_1
        .gun_db()
        .insert_bet(BetState::Proposed {
            local_proposal: local_proposal.clone(),
        })
        .unwrap();

    let (p2_bet_id, encrypted_offer) = {
        let balance = party_2.bdk_wallet().get_balance().unwrap();
        let bet_value = balance - 250;

        assert!(
            matches!(
                party_2
                    .generate_offer_with_oracle_event(
                        local_proposal.proposal.clone(),
                        true,
                        oracle_event.clone(),
                        oracle_info.clone(),
                        BetArgs {
                            value: ValueChoice::Amount(Amount::from_sat(bet_value)),
                            ..Default::default()
                        },
                        FeeSpec::Absolute(Amount::from_sat(501)),
                        &keychain_2
                    )
                    .map(|_| ())
                    .unwrap_err()
                    .downcast()
                    .unwrap(),
                bdk::Error::InsufficientFunds { .. }
            ),
            "we can't afford 501 fee even with extra proposal fee"
        );

        let (bet, local_public_key, mut cipher) = party_2
            .generate_offer_with_oracle_event(
                local_proposal.proposal,
                true,
                oracle_event,
                oracle_info,
                BetArgs {
                    value: ValueChoice::Amount(Amount::from_sat(bet_value)),
                    ..Default::default()
                },
                // we can afford 500
                FeeSpec::Absolute(Amount::from_sat(500)),
                &keychain_2,
            )
            .unwrap();

        let (bet_id, encrypted_offer, offer) = party_2
            .sign_save_and_encrypt_offer(bet, None, local_public_key, &mut cipher)
            .unwrap();

        assert_eq!(offer.change, None);
        assert_eq!(offer.value.as_sat(), bet_value);

        (bet_id, encrypted_offer)
    };

    wait_for_state!(party_2, p2_bet_id, "offered");

    let (decrypted_offer, offer_public_key, rng) = party_1
        .decrypt_offer(p1_bet_id, encrypted_offer, &keychain_1)
        .unwrap();
    let mut validated_offer = party_1
        .validate_offer(
            p1_bet_id,
            decrypted_offer.into_offer(),
            offer_public_key,
            rng,
            &keychain_1,
        )
        .unwrap();
    party_1.sign_validated_offer(&mut validated_offer).unwrap();

    Broadcast::broadcast(
        party_1.bdk_wallet().client(),
        validated_offer.bet.psbt.clone().extract_tx(),
    )
    .unwrap();
    party_1.set_offer_taken(validated_offer).unwrap();
    test_client.generate(1, None);

    wait_for_state!(party_1, p1_bet_id, "confirmed");
    wait_for_state!(party_2, p2_bet_id, "confirmed");
}
