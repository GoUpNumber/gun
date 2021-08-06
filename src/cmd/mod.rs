mod init;
mod oracle;
mod wallet;
use anyhow::Context;
use bdk::{
    bitcoin::{
        consensus::encode,
        util::{address::Payload, psbt::PartiallySignedTransaction as Psbt},
        Address, Amount, Network, Txid,
    },
    blockchain::{AnyBlockchain, ConfigurableBlockchain, EsploraBlockchain},
    database::BatchDatabase,
    sled, Wallet,
};

pub use init::*;
pub mod bet;
pub use bet::*;
pub mod dev;
pub use oracle::*;
use term_table::{row::Row, Table};
pub use wallet::*;

use crate::{
    bet_database::BetDatabase, chrono::NaiveDateTime, config::Config, keychain::Keychain,
    party::Party, psbt_ext::PsbtFeeRate, FeeSpec, ValueChoice,
};
use anyhow::anyhow;
use std::{collections::HashMap, fs, path::PathBuf};

#[derive(Clone, Debug, structopt::StructOpt)]
pub struct BetArgs {
    /// The value you want to risk on the bet e.g all, 0.05BTC
    pub value: ValueChoice,
}

impl From<BetArgs> for crate::party::BetArgs<'_, '_> {
    fn from(args: BetArgs) -> Self {
        crate::party::BetArgs {
            value: args.value,
            ..Default::default()
        }
    }
}

pub enum FeeChoice {
    /// Pay an absolute fee
    Absolute(Amount),
    /// Pay a certain feerate in sats per vbyte
    Rate(f32),
    /// Use the estimated fee required to confirm in a certain number of blocks
    Speed(u32),
}

pub fn load_config(wallet_dir: &PathBuf) -> anyhow::Result<Config> {
    let mut config_file = wallet_dir.clone();
    config_file.push("config.json");

    match config_file.exists() {
        true => {
            let json_config = fs::read_to_string(config_file.clone())?;
            Ok(serde_json::from_str::<Config>(&json_config)?)
        }
        false => {
            return Err(anyhow!(
                "missing config file at {}",
                config_file.as_path().display()
            ))
        }
    }
}

pub fn read_answer(question: String) -> bool {
    use std::io::{self, BufRead};
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();
    println!("{} [y/n]?", question);
    lines
        .find_map(
            |line| match line.unwrap().trim_end().to_lowercase().as_str() {
                "y" => Some(true),
                "n" => Some(false),
                _ => {
                    println!("[y/n]?");
                    None
                }
            },
        )
        .unwrap_or(false)
}

pub fn get_seed_words_file(wallet_dir: &PathBuf) -> PathBuf {
    let mut seed_words_file = wallet_dir.clone();
    seed_words_file.push("seed.txt");
    seed_words_file
}

pub fn load_bet_db(wallet_dir: &PathBuf) -> anyhow::Result<BetDatabase> {
    let mut db_file = wallet_dir.clone();
    db_file.push("database.sled");
    let database = sled::open(db_file.to_str().unwrap())?;
    let bet_db = BetDatabase::new(database.open_tree("bets")?);
    Ok(bet_db)
}

pub fn load_party(
    wallet_dir: &PathBuf,
) -> anyhow::Result<Party<bdk::blockchain::EsploraBlockchain, impl bdk::database::BatchDatabase>> {
    let (wallet, bet_db, keychain, config) = load_wallet(wallet_dir).context("loading wallet")?;
    let party = Party::new(wallet, bet_db, keychain, config.blockchain);
    Ok(party)
}

pub fn load_wallet(
    wallet_dir: &PathBuf,
) -> anyhow::Result<(
    Wallet<EsploraBlockchain, impl BatchDatabase>,
    BetDatabase,
    Keychain,
    Config,
)> {
    use bdk::keys::bip39::{Language, Mnemonic, Seed};

    if !wallet_dir.exists() {
        return Err(anyhow!(
            "No wallet found at {}. Run `gun init` to set a new one up or set --gun-dir.",
            wallet_dir.as_path().display()
        ));
    }

    let config = load_config(&wallet_dir).context("loading configuration")?;
    let keychain = match config.keys {
        crate::config::WalletKeys::SeedWordsFile => {
            let sw_file = get_seed_words_file(&wallet_dir);
            let seed_words = fs::read_to_string(sw_file.clone()).context("loading seed words")?;
            let mnemonic = Mnemonic::from_phrase(&seed_words, Language::English).map_err(|e| {
                anyhow!(
                    "parsing seed phrase in '{}' failed: {}",
                    sw_file.as_path().display(),
                    e
                )
            })?;
            let mut seed_bytes = [0u8; 64];
            let seed = Seed::new(&mnemonic, "");
            seed_bytes.copy_from_slice(seed.as_bytes());
            Keychain::new(seed_bytes)
        }
    };
    let database = {
        let mut db_file = wallet_dir.clone();
        db_file.push("database.sled");
        sled::open(db_file.to_str().unwrap()).context("opening database.sled")?
    };

    let wallet = {
        let wallet_db = database
            .open_tree("wallet")
            .context("opening wallet tree")?;

        let (external_descriptor, internal_descriptor) = match config.kind {
            crate::config::WalletKind::P2wpkh => (
                bdk::template::Bip84(
                    keychain.main_wallet_xprv(config.network),
                    bdk::KeychainKind::External,
                ),
                bdk::template::Bip84(
                    keychain.main_wallet_xprv(config.network),
                    bdk::KeychainKind::Internal,
                ),
            ),
        };

        let esplora = match AnyBlockchain::from_config(&config.blockchain)? {
            AnyBlockchain::Esplora(esplora) => esplora,
            #[allow(unreachable_patterns)]
            _ => return Err(anyhow!("A the moment only esplora is supported")),
        };

        Wallet::new(
            external_descriptor,
            Some(internal_descriptor),
            config.network,
            wallet_db,
            esplora,
        )
        .context("Initializing wallet failed")?
    };

    let bet_db = BetDatabase::new(database.open_tree("bets").context("opening bets tree")?);

    Ok((wallet, bet_db, keychain, config))
}

pub fn load_wallet_db(wallet_dir: &PathBuf) -> anyhow::Result<impl BatchDatabase> {
    let database = {
        let mut db_file = wallet_dir.clone();
        db_file.push("database.sled");
        sled::open(db_file.to_str().unwrap()).context("opening database.sled")?
    };

    Ok(database
        .open_tree("wallet")
        .context("opening wallet tree")?)
}

pub struct TableData {
    col_names: Vec<String>,
    rows: Vec<Vec<Cell>>,
}

#[derive(serde::Serialize)]
#[serde(untagged)]
pub enum Cell {
    String(String),
    Amount(#[serde(with = "bdk::bitcoin::util::amount::serde::as_sat")] Amount),
    Int(u64),
    Empty,
    DateTime(u64),
    List(Vec<Box<Cell>>),
}

impl From<String> for Cell {
    fn from(string: String) -> Self {
        Cell::String(string)
    }
}

pub fn format_amount(amount: Amount) -> String {
    if amount == Amount::ZERO {
        "0".to_string()
    } else {
        let mut string = amount.to_string();
        string.insert(string.len() - 7, ' ');
        string.insert(string.len() - 11, ' ');
        string.trim_end_matches(" BTC").to_string()
    }
}

impl Cell {
    pub fn string<T: core::fmt::Display>(t: T) -> Self {
        Self::String(t.to_string())
    }

    pub fn datetime(dt: NaiveDateTime) -> Self {
        Self::DateTime(dt.timestamp() as u64)
    }

    pub fn render(self) -> String {
        use Cell::*;
        match self {
            String(string) => string,
            Amount(amount) => format_amount(amount),
            Int(integer) => integer.to_string(),
            Empty => "-".into(),
            DateTime(timestamp) => NaiveDateTime::from_timestamp(timestamp as i64, 0)
                .format("%Y-%m-%dT%H:%M:%SZ")
                .to_string(),
            List(list) => list
                .into_iter()
                .map(|x| Cell::render(*x))
                .collect::<Vec<_>>()
                .join("\n"),
        }
    }

    pub fn render_json(self) -> serde_json::Value {
        use Cell::*;
        match self {
            String(string) => serde_json::Value::String(string),
            Amount(amount) => serde_json::Value::Number(amount.as_sat().into()),
            Int(integer) => serde_json::Value::Number(integer.into()),
            DateTime(timestamp) => serde_json::Value::Number(timestamp.into()),
            Empty => serde_json::Value::Null,
            List(list) => serde_json::Value::Array(
                list.into_iter()
                    .map(|x| serde_json::to_value(&*x).unwrap())
                    .collect(),
            ),
        }
    }
}

pub enum CmdOutput {
    Table(TableData),
    Json(serde_json::Value),
    Item(Vec<(&'static str, Cell)>),
    List(Vec<Cell>),
    None,
}

impl CmdOutput {
    pub fn table<S: Into<String>>(col_names: Vec<S>, rows: Vec<Vec<Cell>>) -> Self {
        CmdOutput::Table(TableData {
            col_names: col_names.into_iter().map(Into::into).collect(),
            rows,
        })
    }

    pub fn render(self) -> String {
        use CmdOutput::*;
        match self {
            Table(table_data) => {
                let mut table = term_table::Table::new();
                table.add_row(Row::new(table_data.col_names.to_vec()));
                for row in table_data.rows.into_iter() {
                    table.add_row(Row::new(row.into_iter().map(Cell::render)));
                }
                table.render()
            }
            Json(json) => serde_json::to_string_pretty(&json).unwrap(),
            Item(item) => {
                if item.len() == 1 {
                    return item.into_iter().next().unwrap().1.render();
                }
                let mut table = term_table::Table::new();
                for (key, value) in item {
                    if matches!(value, Cell::Amount(_)) {
                        table.add_row(Row::new(vec![format!("{} (BTC)", key), value.render()]))
                    } else {
                        table.add_row(Row::new(vec![key.to_string(), value.render()]))
                    }
                }
                table.render()
            }
            List(list) => format!(
                "{}",
                list.into_iter()
                    .map(Cell::render)
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
            None => String::new(),
        }
    }

    pub fn render_simple(self) -> String {
        use CmdOutput::*;
        match self {
            Table(table_data) => table_data
                .rows
                .into_iter()
                .map(|row| {
                    row.into_iter()
                        .map(Cell::render)
                        .collect::<Vec<_>>()
                        .join("\t")
                })
                .collect::<Vec<_>>()
                .join("\n"),
            Json(json) => serde_json::to_string(&json).unwrap(),
            Item(item) => {
                if item.len() == 1 {
                    return item.into_iter().next().unwrap().1.render();
                }
                item.into_iter()
                    .map(|(k, v)| format!("{}\t{}", k, v.render()))
                    .collect::<Vec<_>>()
                    .join("\n")
            }
            List(list) => {
                format!(
                    "{}",
                    list.into_iter()
                        .map(Cell::render)
                        .collect::<Vec<_>>()
                        .join("\n")
                )
            }
            None => String::new(),
        }
    }

    pub fn render_json(self) -> serde_json::Value {
        use CmdOutput::*;
        match self {
            Table(table) => {
                let col_names = table.col_names;
                let hash_maps = table
                    .rows
                    .into_iter()
                    .map(|row| {
                        row.into_iter()
                            .enumerate()
                            .map(|(i, cell)| (col_names[i].clone(), cell.render_json()))
                            .collect::<HashMap<_, _>>()
                    })
                    .collect::<Vec<_>>();

                serde_json::to_value(&hash_maps).unwrap()
            }
            Item(item) => serde_json::to_value(&item).unwrap(),
            Json(item) => item,
            List(list) => serde_json::to_value(list).unwrap(),
            None => serde_json::Value::Null,
        }
    }
}

pub fn display_psbt(network: Network, psbt: &Psbt) -> String {
    let mut table = Table::new();
    let mut header = Some("in".to_string());
    for (i, psbt_input) in psbt.inputs.iter().enumerate() {
        let txout = psbt_input.witness_utxo.as_ref().unwrap();
        let input = &psbt.global.unsigned_tx.input[i];
        let _address = Payload::from_script(&txout.script_pubkey)
            .map(|payload| Address { payload, network }.to_string())
            .unwrap_or(txout.script_pubkey.to_string());

        table.add_row(Row::new(vec![
            header.take().unwrap_or("".to_string()),
            input.previous_output.to_string(),
            format_amount(Amount::from_sat(txout.value)),
        ]));
    }

    let mut header = Some("out".to_string());
    for (i, _) in psbt.outputs.iter().enumerate() {
        let txout = &psbt.global.unsigned_tx.output[i];
        let address = Payload::from_script(&txout.script_pubkey)
            .map(|payload| Address { payload, network }.to_string())
            .unwrap_or(txout.script_pubkey.to_string());
        table.add_row(Row::new(vec![
            header.take().unwrap_or("".to_string()),
            address,
            format_amount(Amount::from_sat(txout.value)),
        ]));
    }

    let (fee, feerate) = psbt.fee();
    table.add_row(Row::new(vec![
        "fee",
        &format!("{} (rate s/vb)", feerate.as_sat_vb()),
        &format_amount(fee),
    ]));

    table.render()
}

pub fn decide_to_broadcast(
    network: Network,
    blockchain: &impl bdk::blockchain::Broadcast,
    psbt: Psbt,
    yes: bool,
    print_tx: bool,
) -> anyhow::Result<(CmdOutput, Option<Txid>)> {
    use crate::item;
    if yes
        || read_answer(format!(
            "This is the transaction taht will be broadcast. Ok?\n{}",
            display_psbt(network, &psbt)
        ))
    {
        let tx = psbt.extract_tx();

        if print_tx {
            Ok((
                item! { "tx" => Cell::String(crate::hex::encode(&encode::serialize(&tx))) },
                Some(tx.txid()),
            ))
        } else {
            use bdk::blockchain::Broadcast;
            let txid = tx.txid();
            Broadcast::broadcast(blockchain, tx)?;
            Ok((item! { "txid" => Cell::string(txid)}, Some(txid)))
        }
    } else {
        Ok((CmdOutput::None, None))
    }
}

#[macro_export]
macro_rules! item {
    ($($key:literal => $value:expr),*$(,)?) => {{
        let mut list = vec![];
        $(
            list.push(($key, $value));
        )*
        $crate::cmd::CmdOutput::Item(list)
    }}
}
