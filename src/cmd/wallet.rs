use super::*;
use crate::{bet_database::BetState, item};
use bdk::{
    bitcoin::{Address, OutPoint, Script, Txid},
    blockchain::Broadcast,
    database::Database,
    wallet::AddressIndex,
    KeychainKind, LocalUtxo, SignOptions,
};
use std::collections::HashMap;
use structopt::StructOpt;

pub fn run_balance(wallet_dir: PathBuf) -> anyhow::Result<CmdOutput> {
    let party = load_party(&wallet_dir)?;
    let (in_bet, unclaimed) = party
        .bet_db()
        .list_entities_print_error::<BetState>()
        .filter_map(|(_, bet_state)| match bet_state {
            BetState::Confirmed { bet, .. } | BetState::Unconfirmed { bet, .. } => {
                Some((bet.local_value, Amount::ZERO))
            }
            BetState::Won { bet, .. } | BetState::Claiming { bet, .. } => {
                Some((Amount::ZERO, bet.joint_output_value))
            }
            _ => None,
        })
        .fold((Amount::ZERO, Amount::ZERO), |cur, next| {
            (
                cur.0.checked_add(next.0).unwrap(),
                cur.1.checked_add(next.1).unwrap(),
            )
        });

    let wallet_balance = Amount::from_sat(party.wallet().get_balance()?);

    Ok(item! {
        "main" => Cell::Amount(wallet_balance),
        "unclaimed" => Cell::Amount(unclaimed),
        "locked" => Cell::Amount(in_bet),
    })
}

#[derive(StructOpt, Debug, Clone)]
pub enum AddressOpt {
    /// A new address even if the last one hasn't been used.
    New,
    /// First one that hasn't been used.
    Next,
    /// List
    List,
    /// Show details of an address
    Show { address: Address },
}

pub fn get_address(wallet_dir: &PathBuf, addr_opt: AddressOpt) -> anyhow::Result<CmdOutput> {
    match addr_opt {
        AddressOpt::New => {
            let (wallet, _, _, _) = load_wallet(wallet_dir)?;
            let address = wallet.get_address(AddressIndex::New)?;
            Ok(item! { "address" => address.to_string().into() })
        }
        AddressOpt::Next => {
            let (wallet, _, _, _) = load_wallet(wallet_dir)?;
            let address = wallet.get_address(AddressIndex::LastUnused)?;
            Ok(item! { "address" => address.to_string().into() })
        }
        AddressOpt::List => {
            let wallet_db = load_wallet_db(wallet_dir).context("loading wallet db")?;
            let scripts = wallet_db.iter_script_pubkeys(Some(KeychainKind::External))?;
            let config = load_config(wallet_dir).context("loading config")?;
            let index = wallet_db.get_last_index(KeychainKind::External)?.unwrap();
            let map = index_utxos(&wallet_db)?;
            let rows = scripts
                .iter()
                .take(index as usize + 1)
                .map(|script| {
                    let address = Address::from_script(&script, config.network).unwrap();
                    let value = map
                        .get(script)
                        .map(|utxos| {
                            Amount::from_sat(utxos.iter().map(|utxo| utxo.txout.value).sum())
                        })
                        .unwrap_or(Amount::ZERO);

                    let count = map.get(script).map(Vec::len).unwrap_or(0);

                    vec![
                        Cell::String(address.to_string()),
                        Cell::Amount(value),
                        Cell::Int(count as u64),
                    ]
                })
                .collect();
            Ok(CmdOutput::table(vec!["address", "value", "utxos"], rows))
        }
        AddressOpt::Show { address } => {
            let (wallet, _, _, _) = load_wallet(wallet_dir)?;
            let script_pubkey = address.script_pubkey();
            let output_descriptor = wallet
                .get_descriptor_for_script_pubkey(&address.script_pubkey())?
                .map(|desc| Cell::String(desc.to_string()))
                .unwrap_or(Cell::Empty);
            let keychain = wallet
                .query_db(|db| db.get_path_from_script_pubkey(&script_pubkey))?
                .map(|(keychain, _)| {
                    Cell::string(match keychain {
                        KeychainKind::External => "external",
                        KeychainKind::Internal => "internal",
                    })
                })
                .unwrap_or(Cell::Empty);
            let map = wallet.query_db(|db| index_utxos(db))?;
            let value = map
                .get(&script_pubkey)
                .map(|utxos| Amount::from_sat(utxos.iter().map(|utxo| utxo.txout.value).sum()))
                .unwrap_or(Amount::ZERO);

            let count = map.get(&script_pubkey).map(Vec::len).unwrap_or(0);

            Ok(item! {
                "value" => Cell::Amount(value),
                "n-utxos" => Cell::Int(count as u64),
                "script-pubkey" => Cell::string(address.script_pubkey().asm()),
                "output-descriptor" => output_descriptor,
                "keychain" => keychain,
            })
        }
    }
}

fn index_utxos(wallet_db: &impl BatchDatabase) -> anyhow::Result<HashMap<Script, Vec<LocalUtxo>>> {
    let mut map: HashMap<Script, Vec<LocalUtxo>> = HashMap::new();
    for local_utxo in wallet_db.iter_utxos()?.iter() {
        map.entry(local_utxo.txout.script_pubkey.clone())
            .and_modify(|v| v.push(local_utxo.clone()))
            .or_insert(vec![local_utxo.clone()]);
    }

    Ok(map)
}

#[derive(StructOpt, Debug, Clone)]
pub struct SendOpt {
    /// The address to send the coins to
    to: Address,
    /// The amount to send
    value: ValueChoice,
    /// The transaction fee to attach
    #[structopt(default_value)]
    fee: FeeSpec,
    /// Don't spend winnings
    #[structopt(long)]
    spend_won: bool,
    /// Also spend bets that are already in the "claiming" state replacing the previous
    /// transaction.
    #[structopt(long)]
    bump_claiming: bool,
}

pub fn run_send(wallet_dir: &PathBuf, send_opt: SendOpt) -> anyhow::Result<CmdOutput> {
    let party = load_party(wallet_dir)?;
    let mut builder = party.wallet().build_tx();

    match send_opt.value {
        ValueChoice::All => builder.drain_wallet().drain_to(send_opt.to.script_pubkey()),
        ValueChoice::Amount(amount) => {
            builder.add_recipient(send_opt.to.script_pubkey(), amount.as_sat())
        }
    };

    builder
        .enable_rbf()
        .ordering(bdk::wallet::tx_builder::TxOrdering::Bip69Lexicographic);

    send_opt
        .fee
        .apply_to_builder(party.wallet().client(), &mut builder)
        ?;

    let (mut psbt, bet_ids_claiming) = if send_opt.spend_won {
        party.spend_won_bets(builder, send_opt.bump_claiming)?.expect("Won't be None since builder we pass in is not manually_selected_only")
    } else {
        let (psbt, _) = builder.finish()?;
        (psbt, vec![])
    };

    party.wallet().sign(&mut psbt, SignOptions::default())?;

    let finalized = party
        .wallet()
        .finalize_psbt(&mut psbt, SignOptions::default())?;

    assert!(finalized, "transaction must be finalized at this point");

    let tx = psbt.extract_tx();
    let txid = tx.txid();

    party.set_bets_to_claiming(&bet_ids_claiming, txid)?;

    Broadcast::broadcast(party.wallet().client(), tx)?;

    Ok(item! { "txid" => txid.to_string().into() })
}

#[derive(StructOpt, Debug, Clone)]
pub enum TransactionOpt {
    List,
    Show { txid: Txid },
}

pub fn run_transaction_cmd(
    wallet_dir: &PathBuf,
    opt: TransactionOpt,
) -> anyhow::Result<CmdOutput> {
    use TransactionOpt::*;
    let (wallet, _, _, _) = load_wallet(wallet_dir)?;

    match opt {
        List => {
            let rows = wallet
                .list_transactions(false)?
                .into_iter()
                .map(|tx| {
                    vec![
                        Cell::String(tx.txid.to_string()),
                        tx.height
                            .map(|x| Cell::Int(x.into()))
                            .unwrap_or(Cell::Empty),
                        Cell::DateTime(tx.timestamp),
                        Cell::Amount(Amount::from_sat(tx.sent)),
                        Cell::Amount(Amount::from_sat(tx.received)),
                    ]
                })
                .collect();
            Ok(CmdOutput::table(
                vec!["txid", "height", "seen", "sent", "received"],
                rows,
            ))
        }
        Show { txid } => {
            let tx = wallet
                .list_transactions(false)?
                .into_iter()
                .find(|tx| tx.txid == txid)
                .ok_or(anyhow!("Transaction {} not found", txid))?;

            Ok(item! {
                "txid" => Cell::String(tx.txid.to_string()),
                "sent" => Cell::Amount(Amount::from_sat(tx.sent)),
                "received" => Cell::Amount(Amount::from_sat(tx.received)),
                "seent-at" => Cell::DateTime(tx.timestamp),
                "confirmed-at" => tx.height.map(|height| Cell::Int(height.into())).unwrap_or(Cell::Empty),
                "fee" => Cell::Amount(Amount::from_sat(tx.fees))
            })
        }
    }
}

#[derive(StructOpt, Debug, Clone)]
/// View Unspent Transaction Outputs (UTxOs)
pub enum UtxoOpt {
    /// List UTXOs owned by this wallet
    List,
    /// Show details about a particular UTXO
    Show { outpoint: OutPoint },
}

pub fn run_utxo_cmd(wallet_dir: &PathBuf, opt: UtxoOpt) -> anyhow::Result<CmdOutput> {
    match opt {
        UtxoOpt::List => {
            let (wallet, _, _, _) = load_wallet(wallet_dir)?;
            let rows = wallet
                .list_unspent()?
                .into_iter()
                .map(|utxo| {
                    vec![
                        Cell::String(utxo.outpoint.to_string()),
                        Address::from_script(&utxo.txout.script_pubkey, wallet.network())
                            .map(|address| Cell::String(address.to_string()))
                            .unwrap_or(Cell::Empty),
                        Cell::Amount(Amount::from_sat(utxo.txout.value)),
                    ]
                })
                .collect();

            // TODO: list won bet utxos
            Ok(CmdOutput::table(vec!["outpoint", "address", "value"], rows))
        }
        UtxoOpt::Show { outpoint } => {
            let (wallet, _, _, _) = load_wallet(wallet_dir)?;
            let utxo = wallet
                .query_db(|db| db.get_utxo(&outpoint))?
                .ok_or(anyhow!("UTXO {} not in wallet database", outpoint))?;
            let script_pubkey = utxo.txout.script_pubkey.clone();

            let tx = wallet.query_db(|db| db.get_tx(&utxo.outpoint.txid, false))?;
            let (tx_seen, tx_height) = tx
                .map(|tx| {
                    (
                        Cell::DateTime(tx.timestamp),
                        tx.height
                            .map(|h| Cell::Int(h as u64))
                            .unwrap_or(Cell::Empty),
                    )
                })
                .unwrap_or((Cell::Empty, Cell::Empty));

            let output_descriptor = wallet
                .get_descriptor_for_script_pubkey(&script_pubkey)?
                .map(|desc| Cell::String(desc.to_string()))
                .unwrap_or(Cell::Empty);

            // TODO: show utxos that are associated with won bets
            Ok(item! {
                "outpoint" => Cell::String(utxo.outpoint.to_string()),
                "value" => Cell::Amount(Amount::from_sat(utxo.txout.value)),
                "tx-seen-at" => tx_seen,
                "tx-confirmed-at" => tx_height,
                "address" => Address::from_script(&utxo.txout.script_pubkey, wallet.network())
                            .map(|address| Cell::String(address.to_string()))
                            .unwrap_or(Cell::Empty),
                "script-pubkey" => Cell::String(script_pubkey.asm()),
                "output-descriptor" => output_descriptor,
                "keychain" => Cell::String(match utxo.keychain {
                    KeychainKind::External => "external",
                    KeychainKind::Internal => "internal",
                }.into()),
            })
        }
    }
}
