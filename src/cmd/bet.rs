use crate::{OracleInfo, bet::Bet, bet_database::{BetDatabase, BetState}, party::{Offer, Party, Proposal}};
use anyhow::{anyhow, Context};
use bdk::{bitcoin::Amount, blockchain::Blockchain, database::BatchDatabase, reqwest::Url};
use chacha20::cipher::StreamCipher;
use olivia_core::{Outcome, OutcomeError, Descriptor};
use term_table::{row::Row, Table};

pub fn list_oracles(bet_db: &BetDatabase) -> Table {
    let mut table = Table::new();
    let oracles = bet_db.list_entities_print_error::<OracleInfo>();
    println!("id\tattestation-key\tannouncement-key");
    table.add_row(Row::new(vec!["id", "attestation-key", "announcement-key"]));

    for (oracle_id, oracle_info) in oracles {
        let oracle_keys = oracle_info.oracle_keys;
        table.add_row(Row::new(vec![
            oracle_id,
            oracle_keys.attestation_key.to_string(),
            oracle_keys.announcement_key.to_string(),
        ]));
    }

   table
}

pub async fn propose<B: Blockchain, D: BatchDatabase>(
    party: Party<B, D>,
    event_url: Url,
    value: Amount,
) -> anyhow::Result<Proposal> {
    let (_bet_id, proposal) = party.make_proposal_from_url(event_url, value).await?;
    Ok(proposal)
}

pub fn list_bets(bet_db: &BetDatabase) -> Table {
    let mut table = Table::new();
    table.add_row(Row::new(vec![
        "id",
        "state",
        "expected outcome-time",
        "risk",
        "reward",
        "I bet on",
        "event-url",
    ]));

    for (bet_id, bet_state) in bet_db.list_entities_print_error::<BetState>() {
        let name = String::from(bet_state.name());
        match bet_state {
            BetState::Proposed { local_proposal } => table.add_row(Row::new(vec![
                bet_id.to_string(),
                name,
                local_proposal
                    .oracle_event
                    .event
                    .expected_outcome_time
                    .map(|d| format!("{}", d))
                    .unwrap_or("-".into()),
                local_proposal.proposal.value.to_string(),
                "-".into(),
                "-".into(),
                format!(
                    "https://{}{}",
                    local_proposal.proposal.oracle, local_proposal.proposal.event_id
                ),
            ])),
            BetState::Offered { bet }
            | BetState::Unconfirmed { bet, .. }
            | BetState::Confirmed { bet, .. }
            | BetState::Won { bet, .. }
            | BetState::Lost { bet, .. }
            => table.add_row(Row::new(vec![
                bet_id.to_string(),
                name,
                bet.oracle_event
                   .event
                   .expected_outcome_time
                   .map(|d| format!("{}", d))
                   .unwrap_or("-".into()),
                bet.local_value.to_string(),
                bet.joint_output_value
                   .checked_sub(bet.local_value)
                   .unwrap()
                   .to_string(),
                match bet.i_chose_right {
                    false => bet.oracle_event.event.id.parties().unwrap().0.into(),
                    true => bet.oracle_event.event.id.parties().unwrap().1.into(),
                },
                format!("https://{}{}", bet.oracle_id, bet.oracle_event.event.id),
            ])),
        }
    }

    table
}

pub async fn generate_offer<B: Blockchain, D: BatchDatabase>(
    party: &Party<B, D>,
    proposal: Proposal,
    value: Amount,
    choice: &str,
) -> anyhow::Result<(Bet, Offer, impl StreamCipher)> {
    let event_id = &proposal.event_id;
    if event_id.n_outcomes() != 2 {
        return Err(anyhow!(
            "You can only bet on events with two outcomes but {} has {}",
            event_id,
            event_id.n_outcomes()
        ));
    }
    let outcome =
        Outcome::try_from_id_and_outcome(proposal.event_id.clone(), choice).map_err(|e| -> anyhow::Error {match e {
            OutcomeError::OccurredNotTrue { .. } => {
                unreachable!("not an occur event")
            }
            OutcomeError::InvalidEntity { entity } => {
                anyhow!(
                    "{} is not a valid outcome: {} is not one of the competitors",
                    choice,
                    entity
                )
            }
            OutcomeError::BadFormat => {
                match event_id.descriptor() {
                    Descriptor::Enum { outcomes }  => anyhow!("{} is not a valid outcome. possible outcomes are: {}", choice, outcomes.join(", ")),
                    _ => anyhow!("{} is not a valid outcome.", choice),
                }
            }
        }})?;

    party
        .generate_offer(proposal, outcome.value == 1, value, )
        .await
        .context("failed to generate offer")
}
