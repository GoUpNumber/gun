use super::{read_input, run_oralce_cmd, Cell};
use crate::{
    betting::*,
    cmd::{self, read_yn, CmdOutput},
    item,
    keychain::Keychain,
    psbt_ext::PsbtFeeRate,
    Url, ValueChoice,
};
use anyhow::*;
use bdk::bitcoin::{Address, Amount, Script};
use chacha20::cipher::StreamCipher;
use olivia_core::{chrono::Utc, Outcome, OutcomeError};
use std::{path::PathBuf, str::FromStr};
use structopt::StructOpt;

#[derive(Clone, Debug, structopt::StructOpt)]
pub struct BetArgs {
    /// The value you want to risk on the bet e.g all, 0.05BTC
    #[structopt(short, long)]
    pub value: Option<ValueChoice>,
    /// tag the bet with short string
    #[structopt(short, long)]
    pub tags: Vec<String>,
}

impl BetArgs {
    pub fn prompt_to_core_bet_args(&self, gain: Option<Amount>) -> crate::betting::BetArgs<'_, '_> {
        let prompt = match gain {
            None => "How much value do you want to risk?".to_string(),
            Some(gain) => format!("How much value do you want to risk to gain {}", gain),
        };
        let value = self.value.as_ref().cloned().unwrap_or_else(|| {
            read_input(
                &prompt,
                match gain {
                    None => "e.g. 0.01BTC, 100000sat, all",
                    Some(_) => "match, all or a value like 0.01BTC",
                },
                |input| match (gain, input) {
                    (Some(gain), "match") => Ok(ValueChoice::Amount(gain)),
                    (_, input) => ValueChoice::from_str(input),
                },
            )
        });
        crate::betting::BetArgs {
            value,
            tags: self.tags.clone(),
            ..Default::default()
        }
    }
}

#[derive(StructOpt, Debug, Clone)]
#[structopt(about = "Make or take a bet", rename_all = "kebab")]
pub enum BetOpt {
    /// Propose an event to bet on
    Propose {
        #[structopt(flatten)]
        args: BetArgs,
        /// the HTTP url for the event
        event_url: Url,
        /// Print the proposal without asking
        #[structopt(long, short)]
        yes: bool,
    },
    /// Make an offer to a proposal
    Offer {
        #[structopt(flatten)]
        args: BetArgs,
        /// The propsal string
        proposal: VersionedProposal,
        /// The outcome to choose
        #[structopt(long, short)]
        choice: Option<String>,
        /// Make the offer without asking
        #[structopt(long, short)]
        yes: bool,
        /// Pad the encrypted offer to a certain number of bytes e.g. 385 for twitter
        #[structopt(long, short, default_value = "385")]
        pad: usize,
        #[structopt(flatten)]
        fee_args: cmd::FeeArgs,
        /// Attach an additional message to the offer
        #[structopt(long, short)]
        message: Option<String>,
    },
    /// Inspect an offer or proposal string
    Inspect(InspectOpt),
    /// Take on offer made to your proposal
    Take {
        /// The bet id you are taking the bet from
        id: BetId,
        /// The offer string (a base20248 string)
        encrypted_offer: Ciphertext,
        /// Take the offer and broadacast tx without prompting.
        #[structopt(short, long)]
        yes: bool,
        #[structopt(long)]
        /// Print the bet transaction as hex instead of broadcasting it.
        print_tx: bool,
    },
    /// Claim your winnings
    ///
    /// Spends all "won" bets. Note that this is just shorthand for `gun send` where you send the
    /// coins back to your own wallet address.
    Claim {
        #[structopt(flatten)]
        fee_args: cmd::FeeArgs,
        /// Also spend bets that are already in the "claiming" state replacing the previous
        /// transaction.
        #[structopt(long)]
        bump_claiming: bool,
        /// Print the claim transaction hex but don't broadcast (this assumes you will broadcast the
        /// transaction yourself)
        #[structopt(long)]
        print_tx: bool,
        /// Do not prompt for answers just say yes
        #[structopt(short, long)]
        yes: bool,
    },
    /// List bets
    List,
    /// Show details of a particular bet
    Show {
        /// The id of the bet you want to show.
        id: BetId,
        /// Show the raw entry in the database
        #[structopt(long, short)]
        raw: bool,
    },
    /// Cancel a bet
    Cancel {
        /// The bets to cancel.
        ids: Vec<BetId>,
        #[structopt(flatten)]
        fee_args: cmd::FeeArgs,
        /// Don't prompt for answers just say yes
        #[structopt(short, long)]
        yes: bool,
        /// Print the cancel transaction hex but don't broadcast it (this assumes you will broadcast
        /// the transaction yourself).
        #[structopt(long)]
        print_tx: bool,
    },
    /// Delete all memory of the bet.
    ///
    /// Think carefully before using on unfinished bets. It's usually better to use cancel.
    Forget {
        /// The list of bet ids to forget about
        ids: Vec<BetId>,
    },
    /// Edit list of trusted oracles
    Oracle(crate::cmd::OracleOpt),
    /// Tag a bet
    Tag(TagOpt),
    /// Make a encrypted reply to a proposal
    Reply {
        /// The proposal to send an encrypted message to.
        proposal: VersionedProposal,
        /// The message to send. If not set reads from stdin.
        #[structopt(short, long)]
        message: Option<String>,
        /// Pad the ciphertext to be at least this length.
        #[structopt(short, long, default_value = "385")]
        pad: usize,
    },
}

#[derive(Clone, Debug, StructOpt)]
#[structopt(about = "Inspect a base2048", rename_all = "kebab")]
pub enum InspectOpt {
    /// Inspect a proposal
    Proposal {
        /// The proposal to inspect.
        proposal: VersionedProposal,
    },
    /// Inspect an encrypted offer
    Offer {
        /// The bet id the offer is for.
        id: BetId,
        /// The encrypted offer as a base2048 string.
        encrypted_offer: Ciphertext,
    },
}

#[derive(Clone, Debug, StructOpt)]
pub enum TagOpt {
    /// Add a tag to a bet
    Add {
        /// The bet to attach the tag to.
        id: BetId,
        /// The tag.
        tag: String,
    },
    /// Remove a tag from a bet
    Remove {
        /// The bet to remove the tag from.
        id: BetId,
        /// The tag to remove.
        tag: String,
    },
}

pub fn run_bet_cmd(
    wallet_dir: &PathBuf,
    cmd: BetOpt,
    sync: bool,
) -> anyhow::Result<cmd::CmdOutput> {
    // For now just always do this but we may want to do something more fine grained later.
    if sync {
        let party = cmd::load_party(wallet_dir)?;
        party.sync()?;
        party.poke_bets();
    }

    match cmd {
        BetOpt::Propose {
            args,
            event_url,
            yes,
        } => {
            let party = cmd::load_party(wallet_dir)?;
            let oracle_id = event_url.host_str().unwrap().to_string();
            let now = Utc::now().naive_utc();
            let (oracle_event, _, is_attested) =
                get_oracle_event_from_url(party.bet_db(), event_url)?;
            if is_attested {
                return Err(anyhow!("{} already attested", oracle_event.event.id));
            }

            let mut question = format!(
                "You are proposing a bet on the {}.",
                olivia_describe::event_id_short(&oracle_event.event.id)
            );
            if let Some(expected_outcome_time) = oracle_event.event.expected_outcome_time {
                if expected_outcome_time <= now {
                    return Err(anyhow!(
                        "{} is expected to complete at {} but it's already {}",
                        oracle_event.event.id,
                        expected_outcome_time,
                        now
                    ));
                }
                question += &format!(
                    "\nThe outcome is expected to be known at {} UTC (in {}).",
                    expected_outcome_time,
                    crate::format_dt_diff_till_now(expected_outcome_time)
                );
            }
            question += " Ok";
            let args = args.prompt_to_core_bet_args(None);
            let local_proposal = party.make_proposal(oracle_id, oracle_event, args)?;
            if let Some(change) = &local_proposal.change {
                eprintln!("This proposal will put {} “in-use” unnecessarily because the bet value {} does not match a sum of available utxos.\nYou can get a utxo with the exact amount using `gun split` first.\n--",  change.value(), local_proposal.proposal.value);
            }

            if yes || read_yn(&question) {
                let proposal_string = local_proposal.proposal.clone().into_versioned().to_string();
                let id = party
                    .bet_db()
                    .insert_bet(BetState::Proposed { local_proposal })?;

                eprintln!("post your proposal and let people make offers to it:");
                Ok(CmdOutput::EmphasisedItem {
                    main: ("proposal", Cell::string(proposal_string)),
                    other: vec![("id", Cell::string(id))],
                })
            } else {
                Ok(CmdOutput::None)
            }
        }
        BetOpt::Offer {
            args,
            proposal,
            choice,
            fee_args,
            yes,
            pad,
            message,
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

            let possible_outcomes = (0..2)
                .map(|i| Outcome {
                    id: event_id.clone(),
                    value: i,
                })
                .collect::<Vec<_>>();

            let outcome = match choice {
                Some(choice) => Outcome::try_from_id_and_outcome(event_id.clone(), &choice)
                    .map_err(|e| match e {
                        OutcomeError::Invalid { outcome } => anyhow!(
                            "{} is not a valid outcome. Valid outcomes are {}",
                            outcome,
                            possible_outcomes
                                .iter()
                                .map(Outcome::outcome_string)
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    })?,
                None => read_input(
                    &format!(
                        "The outcomes for this bet are\n{}\nWhat outcome do you want to bet on",
                        possible_outcomes
                            .iter()
                            .map(|o| format!(
                                "{}: {}",
                                o.outcome_string(),
                                olivia_describe::outcome(o).positive
                            ))
                            .collect::<Vec<_>>()
                            .join("\n"),
                    ),
                    &possible_outcomes
                        .iter()
                        .map(Outcome::outcome_string)
                        .collect::<Vec<_>>()
                        .join(", "),
                    |input| Ok(Outcome::try_from_id_and_outcome(event_id.clone(), &input)?),
                ),
            };

            let args = args.prompt_to_core_bet_args(Some(proposal.value));

            let (bet, offer, local_public_key, mut cipher) = party
                .generate_offer_with_oracle_event(
                    proposal,
                    outcome.value == 1,
                    oracle_event,
                    oracle_info,
                    args,
                    fee_args.fee,
                )?;

            if yes || cmd::read_yn(&bet_prompt(&bet)) {
                let (id, encrypted_offer) = party.save_and_encrypt_offer(
                    bet,
                    offer,
                    message,
                    local_public_key,
                    &mut cipher,
                )?;

                eprintln!("Post this offer in reponse to the proposal");
                let (padded_encrypted_offer, overflow) =
                    encrypted_offer.to_string_padded(pad, &mut cipher);
                if let Some(overflow) = overflow {
                    if pad != 0 {
                        eprintln!(
                            "WARNING: this offer is longer than the pad value {} by {} bytes",
                            pad, overflow
                        );
                    }
                }
                Ok(CmdOutput::EmphasisedItem {
                    main: ("offer", Cell::string(padded_encrypted_offer)),
                    other: vec![("id", Cell::string(id))],
                })
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
            let (plaintext, offer_public_key, rng) = party.decrypt_offer(id, encrypted_offer)?;
            match plaintext {
                Plaintext::Offerv1 { offer, message } => {
                    if let Some(message) = message {
                        eprintln!("This message was attached to the offer:\n{}", message);
                    }
                    let validated_offer = party.validate_offer(id, offer, offer_public_key, rng)?;
                    if yes || cmd::read_yn(&bet_prompt(&validated_offer.bet)) {
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
                Plaintext::Messagev1(message) => {
                    eprintln!("The ciphertext contained a secret message:");
                    Ok(item! { "message" => Cell::string(message) })
                }
            }
        }
        BetOpt::Claim {
            fee_args,
            bump_claiming,
            print_tx,
            yes,
        } => {
            let party = cmd::load_party(wallet_dir)?;
            let wallet = party.wallet();
            match party.claim(fee_args.fee, bump_claiming)? {
                Some((ids, claim_psbt)) => {
                    let (output, txid) = cmd::decide_to_broadcast(
                        wallet.network(),
                        wallet.client(),
                        claim_psbt,
                        yes,
                        print_tx,
                    )?;
                    if let Some(txid) = txid {
                        for id in ids {
                            if let Err(e) = party.take_next_action(id, false) {
                                eprintln!("error updating state of bet {} after broadcasting claim tx {}: {}", id, txid, e);
                            }
                        }
                    }
                    Ok(output)
                }
                None => Ok(CmdOutput::None),
            }
        }
        BetOpt::Cancel {
            ids,
            fee_args,
            yes,
            print_tx,
        } => {
            let party = cmd::load_party(wallet_dir)?;
            Ok(match party.generate_cancel_tx(&ids, fee_args.fee)? {
                Some(psbt) => {
                    let (output, txid) = cmd::decide_to_broadcast(
                        party.wallet().network(),
                        party.wallet().client(),
                        psbt,
                        yes,
                        print_tx,
                    )?;

                    if let Some(txid) = txid {
                        for id in ids {
                            if let Err(e) = party.take_next_action(id, true) {
                                eprintln!("error updating state of bet {} after broadcasting cancel tx: {}: {}", id, txid, e);
                            }
                        }
                    }
                    output
                }
                None => {
                    eprintln!("no bets needed canceling");
                    CmdOutput::None
                }
            })
        }
        BetOpt::Forget { ids } => {
            let bet_db = cmd::load_bet_db(wallet_dir)?;
            let mut to_remove = vec![];
            for id in ids {
                match bet_db.get_entity::<BetState>(id) {
                    Ok(Some(bet_state)) => match bet_state {
                        BetState::Proposed { local_proposal } => {
                            match local_proposal.oracle_event.event.expected_outcome_time {
                                Some(expected_outcome_time) if expected_outcome_time < Utc::now().naive_utc() => to_remove.push(id),
                                _ => if cmd::read_yn(&format!("You should only forget a proposal if you are you confident no one will make an offer to it.\nIf you're not sure it's better to cancel it properly using `gun bet cancel`.\nAre you sure you want to forget your proposed bet {}", id)) {
                                    to_remove.push(id);
                                }
                            }
                        },
                        BetState::Offered { .. } => if cmd::read_yn(&format!("Forgetting an offer can lead to loss of funds if it has been seen by the proposer. Are you sure you want to forget bet {}", id)) {
                            to_remove.push(id);
                        },
                        BetState::Won { .. } | BetState::Claimed { height: None, .. } | BetState::Canceled { height: None, .. } | BetState::Included { .. }  => return Err(anyhow!("You may not forget bet {} because it is in the {} state", id, bet_state.name())),
                        _ => to_remove.push(id),
                    },
                    Ok(None) => return Err(anyhow!("Bet {} doesn't exist", id)),
                    Err(_) => {
                        eprintln!("Was unable to retrieve bet {} from the database. Assuming you know what you are doing and forgetting it.", id);
                        to_remove.push(id);
                    }
                }
            }

            for id in &to_remove {
                let _ = bet_db.remove_entity::<BetState>(*id);
            }

            Ok(CmdOutput::List(
                to_remove.into_iter().map(|x| Cell::string(x)).collect(),
            ))
        }
        BetOpt::Show { id, raw } => {
            let party = cmd::load_party(wallet_dir)?;
            let bet_db = party.bet_db();
            let bet_state = bet_db
                .get_entity::<BetState>(id)?
                .ok_or(anyhow!("Bet {} doesn't exist", id))?;

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
                    "inputs" => Cell::List(local_proposal.proposal.inputs.clone().into_iter().map(|x| Box::new(Cell::string(x))).collect()),
                    "change-addr" => local_proposal.change.as_ref().and_then(|change| Address::from_script(change.script(), party.wallet().network())).map(Cell::string).unwrap_or(Cell::Empty),
                    "change-value" => local_proposal.change.as_ref().map(|change| Cell::Amount(change.value())).unwrap_or(Cell::Empty),
                    "tags" => Cell::List(local_proposal.tags.iter().map(Cell::string).map(Box::new).collect()),
                    "string" => Cell::string(local_proposal.proposal.clone().into_versioned()),
                },
                BetOrProp::Bet(bet)
                | BetOrProp::OfferedBet {
                    bet: OfferedBet(bet),
                    ..
                } => item! {
                    "state" => Cell::string(name),
                    "risk" => Cell::Amount(bet.local_value),
                    "reward" => Cell::Amount(bet.joint_output_value.checked_sub(bet.local_value).unwrap()),
                    "i-bet" => Cell::String(Outcome { id: bet.oracle_event.event.id.clone(), value: bet.i_chose_right as u64 }.outcome_string()),
                    "event-id" => Cell::string(&bet.oracle_event.event.id),
                    "oracle" => Cell::string(&bet.oracle_id),
                    "outcome-time" => bet.oracle_event.event.expected_outcome_time.map(Cell::datetime).unwrap_or(Cell::Empty),
                    "my-inputs" => Cell::List(bet.my_inputs().into_iter().map(|x| Box::new(Cell::string(x))).collect()),
                    "bet-outpoint" => Cell::string(bet.outpoint()),
                    "bet-value" => Cell::Amount(bet.joint_output_value),
                    "bet-descriptor" => Cell::string(bet.joint_output.descriptor()),
                    "claim-txid" => match bet_state {
                        BetState::Claimed { txid, .. } => Cell::string(txid),
                        _ => Cell::Empty
                    },
                    "tags" => Cell::List(bet.tags.iter().map(Cell::string).map(Box::new).collect())
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
                id,
                encrypted_offer,
            } => {
                let party = cmd::load_party(wallet_dir)?;
                let bet_state = party
                    .bet_db()
                    .get_entity::<BetState>(id)?
                    .ok_or(anyhow!("unknown bet id {}", id))?;
                match bet_state {
                    BetState::Proposed { local_proposal } => {
                        let event_id = &local_proposal.oracle_event.event.id;
                        let (plaintext, offer_public_key, rng) =
                            party.decrypt_offer(id, encrypted_offer)?;

                        match plaintext {
                            Plaintext::Offerv1 { offer, message } => {
                                let (fee, feerate, valid) = match party.validate_offer(
                                    id,
                                    offer.clone(),
                                    offer_public_key,
                                    rng,
                                ) {
                                    Ok(validated_offer) => {
                                        let (fee, feerate) = validated_offer.bet.psbt.fee();
                                        (Some(fee), Some(feerate), true)
                                    }
                                    Err(_) => (None, None, false),
                                };

                                let Offer {
                                    inputs,
                                    change,
                                    choose_right,
                                    value,
                                } = offer;

                                let chosen_outcome = Outcome {
                                    id: event_id.clone(),
                                    value: choose_right as u64,
                                };

                                item! {
                                    "value" => Cell::Amount(value),
                                    "their-choice" => Cell::string(chosen_outcome.outcome_string()),
                                    "public-key" => Cell::string(&offer_public_key),
                                    "change-script" => change.map(|x| Cell::string(x.script())).unwrap_or(Cell::Empty),
                                    "inputs" => Cell::List(inputs.into_iter().map(|x| Cell::string(x.outpoint)).map(Box::new).collect()),
                                    "valid" => Cell::string(valid),
                                    "fee" => fee.map(Cell::Amount).unwrap_or(Cell::Empty),
                                    "feerate" => feerate.map(|x| Cell::string(x.as_sat_vb())).unwrap_or(Cell::Empty),
                                    "message" => message.map(Cell::string).unwrap_or(Cell::Empty)
                                }
                            }
                            Plaintext::Messagev1(message) => {
                                eprintln!("This ciphertext contained a secret message:");
                                item! { "message" => Cell::string(message) }
                            }
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
        BetOpt::Tag(tagopt) => {
            let bet_db = cmd::load_bet_db(wallet_dir)?;
            match tagopt {
                TagOpt::Add { id, tag } => {
                    bet_db.update_bets(&[id], |mut bet_state, _, _| {
                        bet_state.tags_mut().push(tag.clone());
                        Ok(bet_state)
                    })?;
                    Ok(CmdOutput::None)
                }
                TagOpt::Remove { id, tag } => {
                    bet_db.update_bets(&[id], |mut bet_state, _, _| {
                        bet_state
                            .tags_mut()
                            .retain(|existing_tag| existing_tag != &tag);
                        Ok(bet_state)
                    })?;
                    Ok(CmdOutput::None)
                }
            }
        }
        BetOpt::Reply {
            proposal,
            message,
            pad,
        } => {
            let message = message.unwrap_or_else(|| {
                use std::io::Read;
                let mut words = String::new();
                eprintln!("Type your reply and use CTRL-D to finish it.");
                std::io::stdin().read_to_string(&mut words).unwrap();
                words
            });
            let party = cmd::load_party(wallet_dir)?;
            let (ciphertext, mut cipher) = reply(&party.keychain, proposal, message);
            let (ciphertext_str, overflow) = ciphertext.to_string_padded(pad, &mut cipher);
            if let Some(overflow) = overflow {
                eprintln!(
                    "WARNING: ciphertext is longer than {} -- it needs to be cut down by {} to fit",
                    pad, overflow
                );
            }
            Ok(item! { "ciphertext" => Cell::string(ciphertext_str) })
        }
    }
}

fn reply(
    keychain: &Keychain,
    proposal: VersionedProposal,
    message: String,
) -> (Ciphertext, impl StreamCipher) {
    let (remote_public_key, local_keypair) = match proposal {
        VersionedProposal::One(proposal) => {
            (proposal.public_key, keychain.keypair_for_offer(&proposal))
        }
    };
    let (mut cipher, _) = crate::ecdh::ecdh(&local_keypair, &remote_public_key);
    let ciphertext = Ciphertext::create(
        local_keypair.public_key,
        &mut cipher,
        Plaintext::Messagev1(message),
    );

    (ciphertext, cipher)
}

fn list_bets(bet_db: &BetDatabase) -> CmdOutput {
    let mut rows = vec![];

    for (id, bet_state) in bet_db.list_entities_print_error::<BetState>() {
        let name = String::from(bet_state.name());
        match bet_state.into_bet_or_prop() {
            BetOrProp::Proposal(local_proposal) => rows.push(vec![
                Cell::Int(id.into()),
                Cell::String(name),
                local_proposal
                    .oracle_event
                    .event
                    .expected_outcome_time
                    .map(Cell::datetime)
                    .unwrap_or(Cell::Empty),
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
                Cell::List(
                    local_proposal
                        .tags
                        .iter()
                        .map(Cell::string)
                        .map(Box::new)
                        .collect(),
                ),
                Cell::string(local_proposal.proposal.oracle),
                Cell::Empty,
                Cell::string(local_proposal.proposal.event_id.short_id()),
            ]),
            BetOrProp::Bet(bet)
            | BetOrProp::OfferedBet {
                bet: OfferedBet(bet),
                ..
            } => rows.push(vec![
                Cell::Int(id.into()),
                Cell::String(name),
                bet.oracle_event
                    .event
                    .expected_outcome_time
                    .map(Cell::datetime)
                    .unwrap_or(Cell::Empty),
                Cell::String(
                    bet.oracle_event
                        .event
                        .expected_outcome_time
                        .map(crate::format_dt_diff_till_now)
                        .unwrap_or("-".into()),
                ),
                Cell::Amount(bet.local_value),
                Cell::Amount(bet.joint_output_value.checked_sub(bet.local_value).unwrap()),
                Cell::List(bet.tags.iter().map(Cell::string).map(Box::new).collect()),
                Cell::string(&bet.oracle_id),
                Cell::String(bet.my_outcome().outcome_string()),
                Cell::string(bet.oracle_event.event.id.short_id()),
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
            "tags",
            "oracle",
            "i-bet",
            "short-id",
        ],
        rows,
    )
}

fn get_oracle_event_from_url(
    bet_db: &BetDatabase,
    url: Url,
) -> anyhow::Result<(OracleEvent, OracleInfo, bool)> {
    let oracle_id = url.host_str().ok_or(anyhow!("url {} missing host", url))?;

    let event_response = reqwest::blocking::get(url.clone())?
        .error_for_status()
        .with_context(|| format!("while getting {}", url))?
        .json::<EventResponse>()
        .with_context(|| {
            format!(
                "while decoding the response from {}. Are you sure this is a valid event url?",
                url
            )
        })?;

    let oracle_info = bet_db
        .get_entity::<OracleInfo>(oracle_id.to_string())?
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        ecdh::ecdh,
        keychain::{KeyPair, Keychain},
    };
    use bdk::bitcoin::{Amount, OutPoint};
    use olivia_core::EventId;

    #[test]
    fn make_reply_to_proposal() {
        let keychain = Keychain::new([42u8; 64]);
        let proposal_keypair = KeyPair::from_slice(&[43u8; 32]).unwrap();
        let fixed = VersionedProposal::One(Proposal {
            oracle: "h00.ooo".into(),
            event_id: EventId::from_str("/EPL/match/2021-08-22/ARS_CHE.vs=CHE_win").unwrap(),
            value: Amount::from_str("0.01000000 BTC").unwrap(),
            inputs: vec![OutPoint::from_str(
                "d407fe2bd55b6076ce4c78028dc95b4097dd1e5acbf6ccaa741559a0903f1565:1",
            )
            .unwrap()],
            public_key: proposal_keypair.public_key,
            change_script: Some(
                Address::from_str("bc1qvkswtx2t4y8t6237q753htu4hl4mxm5a9swfjw")
                    .unwrap()
                    .script_pubkey()
                    .into(),
            ),
        });

        let (ciphertext, mut pad_cipher) = reply(&keychain, fixed, "a test message".into());
        let (ciphertext_str, overflow) = &ciphertext.to_string_padded(385, &mut pad_cipher);
        assert!(!overflow.is_some());
        let ciphertext = Ciphertext::from_str(ciphertext_str).unwrap();
        let (mut cipher, _) = ecdh(&proposal_keypair, &ciphertext.public_key);
        match ciphertext.decrypt(&mut cipher).unwrap() {
            Plaintext::Messagev1(message) => assert_eq!(&message, "a test message"),
            _ => panic!("expected a message"),
        }
    }
}
