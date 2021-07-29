use super::{run_oralce_cmd, Cell};
use crate::{
    bet_database::{BetDatabase, BetId, BetOrProp, BetState},
    cmd, item,
    party::{EncryptedOffer, Party, Proposal, VersionedProposal},
    FeeSpec, Url,
};
use anyhow::*;
use bdk::{blockchain::EsploraBlockchain, database::BatchDatabase};
use cmd::CmdOutput;
use olivia_core::{
    chrono::{NaiveDateTime, Utc},
    Descriptor, Outcome, OutcomeError,
};
use std::{path::PathBuf, str::FromStr};
use structopt::StructOpt;

#[derive(StructOpt, Debug, Clone)]
#[structopt(about = "Make or take a bet", rename_all = "kebab")]
pub enum BetOpt {
    /// Propose an event to bet on
    Propose {
        /// the HTTP url for the event
        event_url: Url,

        #[structopt(flatten)]
        args: cmd::BetArgs,
    },
    /// Make an offer to a proposal
    Offer {
        #[structopt(flatten)]
        args: cmd::BetArgs,
        /// The propsal string
        proposal: VersionedProposal,
        /// The outcome to choose
        #[structopt(short)]
        choice: String,
        /// The fee to use
        #[structopt(default_value, long)]
        fee: FeeSpec,
        /// Make the offer without asking
        #[structopt(long, short)]
        yes: bool,
    },
    /// Take on offer made to your proposal
    Take {
        /// The bet id you are taking the bet from
        id: BetId,
        /// The offer string (a base20248 string)
        encrypted_offer: EncryptedOffer,
    },
    /// Claim your winnings
    ///
    /// Spends all "won" bets. Note that this is just shorthand for `gun send` where you send the
    /// coins back to your own wallet address.
    Claim {
        #[structopt(long, default_value)]
        fee: FeeSpec,
        /// Also spend bets that are already in the "claiming" state replacing the previous
        /// transaction.
        #[structopt(long)]
        bump_claiming: bool,
        /// Print the claim transaction hex but don't broadcast (this assumes you will broadcast the
        /// transaction yourself)
        #[structopt(short, long)]
        print_tx: bool,
        /// Do not prompt for answers just say yes
        #[structopt(short, long)]
        yes: bool,
    },
    /// List bets
    List {
        #[structopt(long, short)]
        /// Show list don't check the blockchain to update status
        no_update: bool,
    },
    Show {
        bet_id: BetId,
        /// Show the proposal string
        #[structopt(long, short)]
        proposal: bool,
    },
    /// Cancel a bet
    Cancel {
        /// The bet to cancel
        bet_ids: Vec<BetId>,
    },
    /// Delete all memory of the bet.
    ///
    /// Be careful when using this.
    Forget { bet_ids: Vec<BetId> },
    /// Edit list of trusted oracles
    Oracle(crate::cmd::OracleOpt),
}

pub fn run_bet_cmd(wallet_dir: &PathBuf, cmd: BetOpt) -> anyhow::Result<cmd::CmdOutput> {
    match cmd {
        BetOpt::Propose { args, event_url } => {
            let party = cmd::load_party(wallet_dir)?;
            let oracle_id = event_url.host_str().unwrap().to_string();
            let now = Utc::now().naive_utc();
            let (oracle_event, _, is_attested) =
                get_oracle_event_from_url(party.bet_db(), event_url)?;
            if is_attested {
                return Err(anyhow!("{} already attested", oracle_event.event.id));
            }

            if let Some(expected_outcome_time) = oracle_event.event.expected_outcome_time {
                if expected_outcome_time <= now {
                    return Err(anyhow!(
                        "{} is expected to complete at {} but it's already {}",
                        oracle_event.event.id,
                        expected_outcome_time,
                        now
                    ));
                }
            }
            let (_bet_id, proposal) = party.make_proposal(oracle_id, oracle_event, args.into())?;
            eprintln!("post your proposal and let people make offers to it:");
            Ok(item! { "proposal" => Cell::String(proposal.into_versioned().to_string()) })
        }
        BetOpt::Offer {
            args,
            proposal,
            choice,
            fee,
            yes,
        } => {
            let party = cmd::load_party(wallet_dir)?;
            let proposal: Proposal = proposal.into();
            let event_id = proposal.event_id.clone();
            let now = Utc::now().naive_utc();

            if event_id.n_outcomes() != 2 {
                return Err(anyhow!(
                    "You can only bet on events with two outcomes but {} has {}",
                    event_id,
                    event_id.n_outcomes()
                ));
            }
            let outcome = Outcome::try_from_id_and_outcome(event_id.clone(), &choice).map_err(
                |e| -> anyhow::Error {
                    match e {
                        OutcomeError::Invalid { outcome } => match event_id.descriptor() {
                            Descriptor::Enum { outcomes } => anyhow!(
                                "{} is not a valid outcome. possible outcomes are: {}",
                                choice,
                                outcomes.join(", ")
                            ),
                            _ => anyhow!("{} is not a valid outcome for {}", outcome, event_id,),
                        },
                    }
                },
            )?;

            let event_url =
                Url::parse(&format!("https://{}{}", proposal.oracle, proposal.event_id))?;

            let (oracle_event, oracle_info, is_attested) =
                get_oracle_event_from_url(party.bet_db(), event_url)?;

            if is_attested {
                return Err(anyhow!("{} already attested", oracle_event.event.id));
            }

            if let Some(expected_outcome_time) = oracle_event.event.expected_outcome_time {
                if expected_outcome_time <= now {
                    return Err(anyhow!(
                        "{} is expected to complete at {} but it's already {}",
                        oracle_event.event.id,
                        expected_outcome_time,
                        now
                    ));
                }
            }

            let (bet, offer, cipher) = party.generate_offer_with_oracle_event(
                proposal,
                outcome.value == 1,
                oracle_event,
                oracle_info,
                args.into(),
                fee,
            )?;

            if yes || cmd::read_answer(bet.prompt()) {
                let (_, encrypted_offer) = party.save_and_encrypt_offer(bet, offer, cipher)?;
                Ok(item! { "offer" => Cell::String(encrypted_offer.to_string()) })
            } else {
                Ok(CmdOutput::None)
            }
        }
        BetOpt::Take {
            id,
            encrypted_offer,
        } => {
            let party = cmd::load_party(wallet_dir)?;
            let validated_offer = party.decrypt_and_validate_offer(id, encrypted_offer)?;

            if cmd::read_answer(validated_offer.bet.prompt()) {
                let tx = party.take_offer(validated_offer)?;

                Ok(item! { "txid" => Cell::String(tx.txid().to_string()) })
            } else {
                Ok(CmdOutput::None)
            }
        }
        BetOpt::Claim {
            fee,
            bump_claiming,
            print_tx,
            yes,
        } => {
            let party = cmd::load_party(wallet_dir)?;
            let wallet = party.wallet();
            match party.claim(fee, bump_claiming)? {
                Some((bet_ids, claim_psbt)) => {
                    let (output, txid) = cmd::decide_to_broadcast(
                        wallet.network(),
                        wallet.client(),
                        claim_psbt,
                        yes,
                        print_tx,
                    )?;
                    if let Some(txid) = txid {
                        party.set_bets_to_claiming(&bet_ids, txid)?;
                    }
                    Ok(output)
                }
                None => Ok(CmdOutput::None),
            }
        }
        BetOpt::Cancel { bet_ids } => {
            let party = cmd::load_party(wallet_dir)?;
            let tx = party.cancel(&bet_ids)?;
            match tx {
                Some(tx) => Ok(item! { "txid" => Cell::String(tx.txid().to_string())}),
                None => Ok(CmdOutput::None),
            }
        }
        BetOpt::Forget { bet_ids } => {
            let bet_db = cmd::load_bet_db(wallet_dir)?;
            let mut removed = vec![];
            for bet_id in bet_ids.iter() {
                if bet_db.remove_entity::<BetState>(*bet_id)?.is_some() {
                    removed.push(bet_id);
                }
            }
            Ok(CmdOutput::List(
                removed.into_iter().map(|x| Cell::string(x)).collect(),
            ))
        }
        BetOpt::Show { bet_id, proposal } => {
            let bet_db = cmd::load_bet_db(wallet_dir)?;
            let bet = bet_db
                .get_entity::<BetState>(bet_id)?
                .ok_or(anyhow!("Bet {} doesn't exist"))?;

            if proposal {
                match bet {
                    BetState::Proposed { local_proposal } => Ok(
                        item! { "proposal" => Cell::String(local_proposal.proposal.into_versioned().to_string() )},
                    ),
                    _ => Err(anyhow!("Bet {} is not a propsal")),
                }
            } else {
                Ok(CmdOutput::Json(serde_json::to_value(&bet).unwrap()))
            }
        }
        BetOpt::List { no_update } => {
            if !no_update {
                let party = cmd::load_party(wallet_dir)?;
                poke_bets(&party)
            }
            let bet_db = cmd::load_bet_db(wallet_dir)?;
            Ok(list_bets(&bet_db))
        }
        BetOpt::Oracle(oracle_cmd) => {
            let bet_db = cmd::load_bet_db(wallet_dir)?;
            run_oralce_cmd(bet_db, oracle_cmd)
        }
    }
}

fn list_bets(bet_db: &BetDatabase) -> CmdOutput {
    let mut rows = vec![];

    fn format_dt(dt: NaiveDateTime) -> String {
        use olivia_core::chrono;
        let now = chrono::Utc::now().naive_utc();
        let diff = dt - now;
        if diff > chrono::Duration::zero() {
            format!("{}({}h)", dt, diff.num_hours())
        } else {
            dt.to_string()
        }
    }

    for (bet_id, bet_state) in bet_db.list_entities_print_error::<BetState>() {
        let name = String::from(bet_state.name());
        match bet_state {
            BetState::Proposed { local_proposal }
            | BetState::Cancelling {
                bet_or_prop: BetOrProp::Proposal(local_proposal),
                ..
            }
            | BetState::Cancelled {
                bet_or_prop: BetOrProp::Proposal(local_proposal),
                ..
            } => rows.push(vec![
                Cell::Int(bet_id.into()),
                Cell::String(name),
                Cell::String(
                    local_proposal
                        .oracle_event
                        .event
                        .expected_outcome_time
                        .map(format_dt)
                        .unwrap_or("-".into()),
                ),
                Cell::Amount(local_proposal.proposal.value),
                Cell::Empty,
                Cell::Empty,
                Cell::String(format!(
                    "https://{}{}",
                    local_proposal.proposal.oracle, local_proposal.proposal.event_id
                )),
            ]),
            BetState::Offered { bet, .. }
            | BetState::Unconfirmed { bet, .. }
            | BetState::Confirmed { bet, .. }
            | BetState::Won { bet, .. }
            | BetState::Lost { bet, .. }
            | BetState::Claiming { bet, .. }
            | BetState::Cancelling {
                bet_or_prop: BetOrProp::Bet(bet),
                ..
            }
            | BetState::Cancelled {
                bet_or_prop: BetOrProp::Bet(bet),
                ..
            }
            | BetState::Claimed { bet, .. } => rows.push(vec![
                Cell::Int(bet_id.into()),
                Cell::String(name),
                Cell::String(
                    bet.oracle_event
                        .event
                        .expected_outcome_time
                        .map(format_dt)
                        .unwrap_or("-".into()),
                ),
                Cell::Amount(bet.local_value),
                Cell::Amount(bet.joint_output_value.checked_sub(bet.local_value).unwrap()),
                Cell::String(match bet.i_chose_right {
                    false => bet.oracle_event.event.id.parties().unwrap().0.into(),
                    true => bet.oracle_event.event.id.parties().unwrap().1.into(),
                }),
                Cell::String(format!(
                    "https://{}{}",
                    bet.oracle_id, bet.oracle_event.event.id
                )),
            ]),
        }
    }

    CmdOutput::table(
        vec![
            "id",
            "state",
            "outcome-time",
            "risk",
            "reward",
            "I bet",
            "event-url",
        ],
        rows,
    )
}

fn poke_bets<D: BatchDatabase>(party: &Party<EsploraBlockchain, D>) {
    for (bet_id, _) in party.bet_db().list_entities_print_error::<BetState>() {
        match party.take_next_action(bet_id) {
            Ok(_updated) => {}
            Err(e) => eprintln!("Error trying to take action on bet {}: {:?}", bet_id, e),
        }
    }
}

fn get_oracle_event_from_url(
    bet_db: &BetDatabase,
    url: Url,
) -> anyhow::Result<(crate::OracleEvent, crate::OracleInfo, bool)> {
    let oracle_id = url.host_str().ok_or(anyhow!("url {} missing host", url))?;

    let event_response = reqwest::blocking::get(url.clone())?
        .error_for_status()?
        .json::<olivia_core::http::EventResponse<olivia_secp256k1::Secp256k1>>()?;

    let oracle_info = bet_db
        .get_entity::<crate::OracleInfo>(oracle_id.to_string())?
        .ok_or(anyhow!(
            "oracle '{}' is not trusted -- run `gun bet oracle add '{}' to trust it",
            oracle_id,
            oracle_id
        ))?;

    let event_id = olivia_core::EventId::from_str(url.path())
        .with_context(|| format!("trying to parse the path of {} for ", &url))?;

    let oracle_event = event_response
        .announcement
        .verify_against_id(&event_id, &oracle_info.oracle_keys.announcement_key)
        .ok_or(anyhow!("announcement oracle returned from {}", url))?;

    let is_attested = event_response.attestation.is_some();

    Ok((oracle_event, oracle_info, is_attested))
}
