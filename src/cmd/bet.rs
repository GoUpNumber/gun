use super::{run_oralce_cmd, Cell};
use crate::{
    bet::Bet,
    bet_database::{BetDatabase, BetId, BetOrProp, BetState},
    cmd, item,
    party::{EncryptedOffer, Offer, Party, Proposal, VersionedProposal},
    psbt_ext::PsbtFeeRate,
    FeeSpec, Url,
};
use anyhow::*;
use bdk::{bitcoin::Script, blockchain::EsploraBlockchain, database::BatchDatabase};
use cmd::CmdOutput;
use olivia_core::{chrono::Utc, Descriptor, Outcome, OutcomeError};
use std::{path::PathBuf, str::FromStr};
use structopt::StructOpt;

#[derive(StructOpt, Debug, Clone)]
#[structopt(about = "Make or take a bet", rename_all = "kebab")]
pub enum BetOpt {
    /// Propose an event to bet on
    Propose {
        #[structopt(flatten)]
        args: cmd::BetArgs,
        /// the HTTP url for the event
        event_url: Url,
    },
    /// Make an offer to a proposal
    Offer {
        #[structopt(flatten)]
        args: cmd::BetArgs,
        /// The propsal string
        proposal: VersionedProposal,
        /// The outcome to choose
        choice: String,
        /// The transaction fee to attach e.g. spb:4.5 (4.5 sats-per-byte), abs:300 (300 sats absolute
        /// fee), in-blocks:3 (set fee so that it is included in the next three blocks)
        #[structopt(default_value, long)]
        fee: FeeSpec,
        /// Make the offer without asking
        #[structopt(long, short)]
        yes: bool,
        /// Pad the encrypted offer to a certain number of bytes e.g. 385 for twitter
        #[structopt(long, short, default_value = "385")]
        pad: usize,
    },
    /// Inspect an offer or proposal
    Inspect(InspectOpt),
    // Msg {
    //     /// Proposal to make the message to
    //     proposal: VersionedProposal,
    //     ///
    //     message: String
    // },
    /// Take on offer made to your proposal
    Take {
        /// The bet id you are taking the bet from
        id: BetId,
        /// The offer string (a base20248 string)
        encrypted_offer: EncryptedOffer,
        /// Take the offer and broadacast tx without prompting.
        #[structopt(short, long)]
        yes: bool,
        #[structopt(short, long)]
        /// Print the bet transaction as hex instead of broadcasting it.
        print_tx: bool,
    },
    /// Claim your winnings
    ///
    /// Spends all "won" bets. Note that this is just shorthand for `gun send` where you send the
    /// coins back to your own wallet address.
    Claim {
        /// The transaction fee to attach e.g. spb:4.5 (4.5 sats-per-byte), abs:300 (300 sats absolute
        /// fee), in-blocks:3 (set fee so that it is included in the next three blocks)
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
    List,
    Show {
        bet_id: BetId,
        /// Show the raw entry in the database
        #[structopt(long, short)]
        raw: bool,
    },
    /// Cancel a bet
    Cancel {
        /// The bet to cancel
        bet_ids: Vec<BetId>,
        /// The transaction fee to attach e.g. spb:4.5 (4.5 sats-per-byte), abs:300 (300 sats absolute
        /// fee), in-blocks:3 (set fee so that it is included in the next three blocks)
        fee: FeeSpec,
        /// Don't prompt for answers just say yes
        #[structopt(short, long)]
        yes: bool,
        /// Print the cancel transaction hex but don't broadcast it (this assumes you will broadcast
        /// the transaction yourself).
        #[structopt(short, long)]
        print_tx: bool,
    },
    /// Delete all memory of the bet.
    ///
    /// Be careful when using this.
    Forget { bet_ids: Vec<BetId> },
    /// Edit list of trusted oracles
    Oracle(crate::cmd::OracleOpt),
}

#[derive(Clone, Debug, StructOpt)]
#[structopt(about = "Make or take a bet", rename_all = "kebab")]
pub enum InspectOpt {
    /// Inspect a proposal
    Proposal {
        /// The proposal to inspect.
        proposal: VersionedProposal,
    },
    /// Inspect an encrypted offer
    Offer {
        /// The bet id the offer is for.
        bet_id: BetId,
        /// The encrypted offer.
        encrypted_offer: EncryptedOffer,
    },
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
            pad,
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

            let (bet, offer, mut cipher) = party.generate_offer_with_oracle_event(
                proposal,
                outcome.value == 1,
                oracle_event,
                oracle_info,
                args.into(),
                fee,
            )?;

            if yes || cmd::read_answer(bet_prompt(&bet)) {
                let (_, encrypted_offer) = party.save_and_encrypt_offer(bet, offer, &mut cipher)?;
                eprintln!("Post this offer in reponse to the proposal");
                Ok(
                    item! { "offer" => Cell::String(encrypted_offer.to_string_padded(pad, &mut cipher)) },
                )
            } else {
                Ok(CmdOutput::None)
            }
        }
        BetOpt::Take {
            id,
            encrypted_offer,
            yes,
            print_tx,
        } => {
            let party = cmd::load_party(wallet_dir)?;
            let validated_offer = party.decrypt_and_validate_offer(id, encrypted_offer)?;

            if yes || cmd::read_answer(bet_prompt(&validated_offer.bet)) {
                let (output, txid) = cmd::decide_to_broadcast(
                    party.wallet().network(),
                    party.wallet().client(),
                    validated_offer.bet.psbt.clone(),
                    yes,
                    print_tx,
                )?;
                if let Some(_) = txid {
                    party.set_offer_taken(validated_offer)?;
                }
                Ok(output)
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
        BetOpt::Cancel {
            bet_ids,
            fee,
            yes,
            print_tx,
        } => {
            let party = cmd::load_party(wallet_dir)?;
            Ok(match party.generate_cancel_tx(&bet_ids, fee)? {
                Some(psbt) => {
                    let (output, txid) = cmd::decide_to_broadcast(
                        party.wallet().network(),
                        party.wallet().client(),
                        psbt,
                        yes,
                        print_tx,
                    )?;
                    if let Some(txid) = txid {
                        party.set_bets_to_cancelling(&bet_ids[..], txid)?;
                    }
                    output
                }
                None => {
                    eprintln!("no bets needed cancelling");
                    CmdOutput::None
                }
            })
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
        BetOpt::Show { bet_id, raw } => {
            let bet_db = cmd::load_bet_db(wallet_dir)?;
            let bet_state = bet_db
                .get_entity::<BetState>(bet_id)?
                .ok_or(anyhow!("Bet {} doesn't exist", bet_id))?;

            if raw {
                return Ok(CmdOutput::Json(serde_json::to_value(&bet_state).unwrap()));
            }

            let name = bet_state.name();

            Ok(match bet_state.clone().into_bet_or_prop() {
                BetOrProp::Proposal(local_proposal) => item! {
                    "state" => Cell::string(name),
                    "risk" => Cell::Amount(local_proposal.proposal.value),
                    "event-id" => Cell::string(&local_proposal.proposal.event_id),
                    "oracle" => Cell::string(&local_proposal.proposal.oracle),
                    "outcome-time" => local_proposal.oracle_event.event.expected_outcome_time.map(Cell::datetime).unwrap_or(Cell::Empty),
                    "my-inputs" => Cell::List(local_proposal.proposal.inputs.clone().into_iter().map(|x| Box::new(Cell::string(x))).collect()),
                    "change-addr" => Cell::string(&local_proposal.proposal.change_script.is_some()),
                    "string" => Cell::string(local_proposal.proposal.clone().into_versioned()),
                },
                BetOrProp::Bet(bet) => item! {
                    "state" => Cell::string(name),
                    "risk" => Cell::Amount(bet.local_value),
                    "reward" => Cell::Amount(bet.joint_output_value.checked_sub(bet.local_value).unwrap()),
                    "I-bet" => Cell::String(Outcome { id: bet.oracle_event.event.id.clone(), value: bet.i_chose_right as u64 }.outcome_string()),
                    "event-id" => Cell::string(&bet.oracle_event.event.id),
                    "oracle" => Cell::string(&bet.oracle_id),
                    "outcome-time" => bet.oracle_event.event.expected_outcome_time.map(Cell::datetime).unwrap_or(Cell::Empty),
                    "my-inputs" => Cell::List(bet.my_inputs().into_iter().map(|x| Box::new(Cell::string(x))).collect()),
                    "bet-outpoint" => Cell::string(bet.outpoint()),
                    "bet-value" => Cell::Amount(bet.joint_output_value),
                },
            })
        }
        BetOpt::List => {
            let bet_db = cmd::load_bet_db(wallet_dir)?;
            Ok(list_bets(&bet_db))
        }
        BetOpt::Oracle(oracle_cmd) => {
            let bet_db = cmd::load_bet_db(wallet_dir)?;
            run_oralce_cmd(bet_db, oracle_cmd)
        }
        BetOpt::Inspect(inspect_cmd) => Ok(match inspect_cmd {
            InspectOpt::Proposal {
                proposal:
                    VersionedProposal::One(Proposal {
                        oracle,
                        event_id,
                        value,
                        inputs,
                        public_key,
                        change_script,
                    }),
            } => item! {
                "oracle" => Cell::string(oracle),
                "event-id" => Cell::string(event_id),
                "value" => Cell::Amount(value),
                "inputs" => Cell::List(inputs.into_iter().map(|x| Box::new(Cell::string(x))).collect()),
                "public-key" => Cell::string(public_key),
                "change-script" => change_script.map(|x| Cell::string(Script::from(x))).unwrap_or(Cell::Empty)
            },
            InspectOpt::Offer {
                bet_id,
                encrypted_offer,
            } => {
                let party = cmd::load_party(wallet_dir)?;
                let bet_state = party
                    .bet_db()
                    .get_entity::<BetState>(bet_id)?
                    .ok_or(anyhow!("unknown bet id {}", bet_id))?;
                match bet_state {
                    BetState::Proposed { local_proposal } => {
                        let event_id = &local_proposal.oracle_event.event.id;
                        let Offer {
                            inputs,
                            change,
                            public_key,
                            choose_right,
                            value,
                        } = party.decrypt_offer(bet_id, encrypted_offer.clone())?.offer;
                        let (fee, feerate, valid) =
                            match party.decrypt_and_validate_offer(bet_id, encrypted_offer) {
                                Ok(validated_offer) => {
                                    let (fee, feerate) = validated_offer.bet.psbt.fee();
                                    (Some(fee), Some(feerate), true)
                                }
                                Err(_) => (None, None, false),
                            };

                        let chosen_outcome = Outcome {
                            id: event_id.clone(),
                            value: choose_right as u64,
                        };

                        item! {
                            "value" => Cell::Amount(value),
                            "their-choice" => Cell::string(chosen_outcome.outcome_string()),
                            "public-key" => Cell::string(&public_key),
                            "change-script" => change.map(|x| Cell::string(x.script())).unwrap_or(Cell::Empty),
                            "inputs" => Cell::List(inputs.into_iter().map(|x| Cell::string(x.outpoint)).map(Box::new).collect()),
                            "valid" => Cell::string(valid),
                            "fee" => fee.map(Cell::Amount).unwrap_or(Cell::Empty),
                            "feerate" => feerate.map(|x| Cell::string(x.as_sat_vb())).unwrap_or(Cell::Empty)
                        }
                    }
                    _ => {
                        return Err(anyhow!(
                            "inspecting an offer when not in proposed state is not supported yet!"
                        ))
                    }
                }
            }
        }),
    }
}

fn list_bets(bet_db: &BetDatabase) -> CmdOutput {
    let mut rows = vec![];

    for (bet_id, bet_state) in bet_db.list_entities_print_error::<BetState>() {
        let name = String::from(bet_state.name());
        match bet_state.into_bet_or_prop() {
            BetOrProp::Proposal(local_proposal) => rows.push(vec![
                Cell::Int(bet_id.into()),
                Cell::String(name),
                Cell::String(
                    local_proposal
                        .oracle_event
                        .event
                        .expected_outcome_time
                        .map(|x| format!("{}", x))
                        .unwrap_or("-".into()),
                ),
                Cell::String(
                    local_proposal
                        .oracle_event
                        .event
                        .expected_outcome_time
                        .map(crate::format_dt_diff_till_now)
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
            BetOrProp::Bet(bet) => rows.push(vec![
                Cell::Int(bet_id.into()),
                Cell::String(name),
                Cell::String(
                    bet.oracle_event
                        .event
                        .expected_outcome_time
                        .map(|x| format!("{}", x))
                        .unwrap_or("-".into()),
                ),
                Cell::String(
                    bet.oracle_event
                        .event
                        .expected_outcome_time
                        .map(crate::format_dt_diff_till_now)
                        .unwrap_or("-".into()),
                ),
                Cell::Amount(bet.local_value),
                Cell::Amount(bet.joint_output_value.checked_sub(bet.local_value).unwrap()),
                Cell::String(bet.my_outcome().outcome_string()),
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
            "in",
            "risk",
            "reward",
            "i-bet",
            "event-url",
        ],
        rows,
    )
}

pub fn poke_bets<D: BatchDatabase>(party: &Party<EsploraBlockchain, D>) {
    for (bet_id, _) in party.bet_db().list_entities_print_error::<BetState>() {
        match party.take_next_action(bet_id, true) {
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
        .verify_against_id(&event_id, &oracle_info.oracle_keys.announcement)
        .ok_or(anyhow!("Invalid oracle announcement returned from {}", url))?;

    let is_attested = event_response.attestation.is_some();

    Ok((oracle_event, oracle_info, is_attested))
}

fn bet_prompt(bet: &Bet) -> String {
    use std::fmt::Write;
    use term_table::{row::Row, Table};
    let mut res = String::new();
    let i_risk = bet.local_value;
    let i_gain = bet.joint_output_value - i_risk;
    let oracle = &bet.oracle_id;
    let expected_outcome_time = bet.oracle_event.event.expected_outcome_time;
    let id = &bet.oracle_event.event.id;
    let outcome = Outcome {
        id: id.clone(),
        value: bet.i_chose_right as u64,
    };

    let (fee, feerate) = bet.psbt.fee();

    let mut table = Table::new();
    table.add_row(Row::new(vec!["event-id".into(), id.to_string()]));
    table.add_row(Row::new(vec!["oracle", oracle]));
    table.add_row(Row::new(vec!["risk".into(), i_risk.to_string()]));
    table.add_row(Row::new(vec!["reward".into(), i_gain.to_string()]));
    table.add_row(Row::new(vec![
        "ratio".into(),
        format!("{:.3}", i_risk.as_sat() as f64 / i_gain.as_sat() as f64),
    ]));
    table.add_row(Row::new(vec![
        "fee".into(),
        format!("{} ({} s/vb)", fee, feerate.as_sat_vb()),
    ]));

    if let Some(time) = expected_outcome_time {
        table.add_row(Row::new(vec![
            "outcome-time".into(),
            format!("{} (in {})", time, crate::format_dt_diff_till_now(time)),
        ]));
    }

    write!(&mut res, "{}", table.render()).unwrap();
    write!(&mut res, "\n").unwrap();
    write!(
        &mut res,
        "You are betting that {}",
        olivia_describe::outcome(&outcome).positive
    )
    .unwrap();
    write!(&mut res, "\n").unwrap();
    write!(&mut res, "Do you want to take this bet?").unwrap();
    res
}
