mod init;
mod oracle;
use crate::{
    config::GunSigner,
    keychain::ProtocolSecret,
    signers::{PsbtDirSigner, PwSeedSigner, XKeySigner},
    wallet::GunWallet,
};
mod wallet;
use anyhow::Context;
use bdk::{
    bitcoin::{
        consensus::encode,
        util::{
            address::Payload, bip32::ExtendedPrivKey, psbt::PartiallySignedTransaction as Psbt,
        },
        Address, Amount, Network, Txid,
    },
    blockchain::{ConfigurableBlockchain, EsploraBlockchain},
    database::BatchDatabase,
    signer::Signer,
    sled,
    wallet::signer::SignerOrdering,
    KeychainKind, Wallet,
};
use std::sync::Arc;

pub use init::*;
pub mod bet;
pub use bet::*;
pub use oracle::*;
use term_table::{row::Row, Table};
pub use wallet::*;

use crate::{
    chrono::NaiveDateTime,
    config::{Config, VersionedConfig},
    database::GunDatabase,
    keychain::Keychain,
    psbt_ext::PsbtFeeRate,
    FeeSpec, ValueChoice,
};
use anyhow::anyhow;
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, structopt::StructOpt)]
pub struct FeeArgs {
    /// The transaction fee to attach e.g. rate:4.5 (4.5 sats-per-byte), abs:300 (300 sats absolute
    /// fee), in-blocks:3 (set fee so that it is included in the next three blocks).
    #[structopt(default_value, long)]
    fee: FeeSpec,
}

pub enum FeeChoice {
    /// Pay an absolute fee
    Absolute(Amount),
    /// Pay a certain feerate in sats per vbyte
    Rate(f32),
    /// Use the estimated fee required to confirm in a certain number of blocks
    Speed(u32),
}

pub fn load_config(wallet_dir: &std::path::Path) -> anyhow::Result<Config> {
    let mut config_file = wallet_dir.to_path_buf();
    config_file.push("config.json");

    match config_file.exists() {
        true => {
            let json_config = fs::read_to_string(config_file.clone())?;
            Ok(serde_json::from_str::<VersionedConfig>(&json_config)
                .context("Perhaps you are trying to load an old config?")?
                .into())
        }
        false => {
            return Err(anyhow!(
                "missing config file at {}",
                config_file.as_path().display()
            ))
        }
    }
}

pub fn read_yn(question: &str) -> bool {
    use std::io::{self, BufRead};
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();
    eprint!("> {} [y/n]? ", question.replace('\n', "\n> "));
    lines
        .find_map(
            |line| match line.unwrap().trim_end().to_lowercase().as_str() {
                "y" => Some(true),
                "n" => Some(false),
                _ => {
                    eprint!("[y/n]? ");
                    None
                }
            },
        )
        .unwrap_or(false)
}

pub fn read_input<V>(
    prompt: &str,
    possible: &str,
    validator: impl Fn(&str) -> anyhow::Result<V>,
) -> V {
    use std::io::{self, BufRead};
    let stdin = io::stdin();
    let lines = stdin.lock().lines().map(|x| x.unwrap());
    eprint!("> {} [{}]? ", prompt.replace('\n', "\n> "), possible);
    for line in lines {
        match validator(line.trim_end()) {
            Ok(v) => return v,
            Err(_) => eprintln!("> ‘{}’ isn't valid. Try again [{}]", line, possible),
        }
    }
    eprintln!("STDIN terminated");
    std::process::exit(2)
}

pub fn get_seed_words_file(wallet_dir: &Path) -> PathBuf {
    let mut seed_words_file = wallet_dir.to_path_buf();
    seed_words_file.push("seed.txt");
    seed_words_file
}

pub fn load_wallet(
    wallet_dir: &std::path::Path,
) -> anyhow::Result<(GunWallet, Option<Keychain>, Config)> {
    use bdk::keys::bip39::Mnemonic;

    if !wallet_dir.exists() {
        return Err(anyhow!(
            "No wallet found at {}. Run `gun init` to set a new one up or set --gun-dir.",
            wallet_dir.display()
        ));
    }

    let config = load_config(wallet_dir).context("loading configuration")?;
    let database = {
        let mut db_file = wallet_dir.to_path_buf();
        db_file.push("database.sled");
        sled::open(db_file.to_str().unwrap()).context("opening database.sled")?
    };

    let wallet_db = database
        .open_tree("wallet")
        .context("opening wallet tree")?;

    let esplora = EsploraBlockchain::from_config(config.blockchain_config())?;

    let mut wallet = Wallet::new(
        &config.descriptor_external,
        config.descriptor_internal.as_ref(),
        config.network,
        wallet_db,
        esplora,
    )
    .context("Initializing wallet from descriptors")?;

    for (i, signer) in config.signers.iter().enumerate() {
        let signer: Arc<dyn Signer> = match signer {
            GunSigner::PsbtDir {
                path: psbt_signer_dir,
            } => Arc::new(PsbtDirSigner::create(
                psbt_signer_dir.to_owned(),
                config.network,
            )),
            GunSigner::SeedWordsFile {
                file_path,
                passphrase_fingerprint,
            } => {
                let seed_words =
                    fs::read_to_string(file_path.clone()).context("loading seed words")?;
                let mnemonic = Mnemonic::parse(&seed_words).map_err(|e| {
                    anyhow!(
                        "parsing seed phrase in '{}' failed: {}",
                        file_path.as_path().display(),
                        e
                    )
                })?;
                // Any passphrase is added later within PwSeedSigner
                let seed_bytes = mnemonic.to_seed("");
                let master_xpriv =
                    ExtendedPrivKey::new_master(config.network, &seed_bytes).unwrap();

                match passphrase_fingerprint {
                    Some(fingerprint) => Arc::new(PwSeedSigner {
                        mnemonic,
                        network: config.network,
                        master_fingerprint: *fingerprint,
                    }),
                    None => Arc::new(XKeySigner {
                        master_xkey: master_xpriv,
                    }),
                }
            }
        };
        wallet.add_signer(
            KeychainKind::External, //NOTE: will sign internal inputs as well!
            SignerOrdering(i),
            signer,
        );
    }

    let gun_db = GunDatabase::new(database.open_tree("gun").context("opening gun db tree")?);
    let keychain = gun_db.get_entity::<ProtocolSecret>(())?.map(Keychain::from);
    let gun_wallet = GunWallet::new(wallet, gun_db);

    Ok((gun_wallet, keychain, config))
}

pub fn load_wallet_db(wallet_dir: &std::path::Path) -> anyhow::Result<impl BatchDatabase> {
    let database = {
        let mut db_file = wallet_dir.to_path_buf();
        db_file.push("database.sled");
        sled::open(db_file.to_str().unwrap()).context("opening database.sled")?
    };

    database.open_tree("wallet").context("opening wallet tree")
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
    List(Vec<Cell>),
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

pub fn sanitize_str(string: &mut String) {
    string.retain(|c| !c.is_control());
}

impl Cell {
    pub fn string<T: core::fmt::Display>(t: T) -> Self {
        let mut string = t.to_string();
        // Remove control characters to prevent tricks
        sanitize_str(&mut string);
        Self::String(string)
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
                .format("%Y-%m-%dT%H:%M:%S")
                .to_string(),
            List(list) => list
                .into_iter()
                .map(Cell::render)
                .collect::<Vec<_>>()
                .join("\n"),
        }
    }

    pub fn render_tabs(self) -> String {
        use Cell::*;
        match self {
            String(string) => string,
            Amount(amount) => amount.as_sat().to_string(),
            Int(integer) => integer.to_string(),
            Empty => "".into(),
            DateTime(timestamp) => NaiveDateTime::from_timestamp(timestamp as i64, 0)
                .format("%Y-%m-%dT%H:%M:%S")
                .to_string(),
            List(list) => list
                .into_iter()
                .map(Cell::render_tabs)
                .collect::<Vec<_>>()
                .join(" "),
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
                    .map(|x| serde_json::to_value(&x).unwrap())
                    .collect(),
            ),
        }
    }
}

pub enum CmdOutput {
    Table(TableData),
    Json(serde_json::Value),
    Item(Vec<(&'static str, Cell)>),
    /// An item where one field is deemed the "main" one.
    /// Normally the main one will be printed.
    EmphasisedItem {
        main: (&'static str, Cell),
        other: Vec<(&'static str, Cell)>,
    },
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

    pub fn render(self) -> Option<String> {
        use CmdOutput::*;

        Some(match self {
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
            List(list) => list
                .into_iter()
                .map(Cell::render)
                .collect::<Vec<_>>()
                .join("\n"),
            EmphasisedItem { main, .. } => main.1.render(),
            None => return Option::None,
        })
    }

    pub fn render_simple(self) -> String {
        use CmdOutput::*;
        match self {
            Table(table_data) => table_data
                .rows
                .into_iter()
                .map(|row| {
                    row.into_iter()
                        .map(Cell::render_tabs)
                        .collect::<Vec<_>>()
                        .join("\t")
                })
                .collect::<Vec<_>>()
                .join("\n"),
            Json(json) => serde_json::to_string(&json).unwrap(),
            Item(item) => item
                .into_iter()
                .map(|(k, v)| format!("{}\t{}", k, v.render_tabs()))
                .collect::<Vec<_>>()
                .join("\n"),
            EmphasisedItem { main, other } => core::iter::once(main)
                .chain(other.into_iter())
                .map(|(k, v)| format!("{}\t{}", k, v.render_tabs()))
                .collect::<Vec<_>>()
                .join("\n"),
            List(list) => list
                .into_iter()
                .map(Cell::render_tabs)
                .collect::<Vec<_>>()
                .join("\t"),
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
            Item(item) => {
                serde_json::to_value(&item.into_iter().collect::<HashMap<_, _>>()).unwrap()
            }
            EmphasisedItem { main, other } => serde_json::to_value(
                core::iter::once(main)
                    .chain(other.into_iter())
                    .collect::<HashMap<_, _>>(),
            )
            .unwrap(),
            Json(item) => item,
            List(list) => serde_json::to_value(list).unwrap(),
            None => serde_json::Value::Null,
        }
    }
}

pub fn display_psbt(network: Network, psbt: &Psbt) -> String {
    let mut table = Table::new();
    let mut header = Some("in".to_string());
    let mut input_total = Amount::ZERO;
    for (i, psbt_input) in psbt.inputs.iter().enumerate() {
        let txout = psbt_input.witness_utxo.as_ref().unwrap();
        let input = &psbt.unsigned_tx.input[i];
        let _address = Payload::from_script(&txout.script_pubkey)
            .map(|payload| Address { payload, network }.to_string())
            .unwrap_or(txout.script_pubkey.to_string());
        let value = Amount::from_sat(txout.value);
        table.add_row(Row::new(vec![
            header.take().unwrap_or("".to_string()),
            input.previous_output.to_string(),
            format_amount(value),
        ]));
        input_total += value;
    }
    table.add_row(Row::new(vec![
        "".to_string(),
        "total".into(),
        format_amount(input_total),
    ]));

    let mut output_total = Amount::ZERO;
    let mut header = Some("out".to_string());
    for (i, _) in psbt.outputs.iter().enumerate() {
        let txout = &psbt.unsigned_tx.output[i];
        let address = Payload::from_script(&txout.script_pubkey)
            .map(|payload| Address { payload, network }.to_string())
            .unwrap_or(txout.script_pubkey.to_string());
        let value = Amount::from_sat(txout.value);
        table.add_row(Row::new(vec![
            header.take().unwrap_or("".to_string()),
            address,
            format_amount(value),
        ]));
        output_total += value;
    }

    table.add_row(Row::new(vec![
        "".to_string(),
        "total".into(),
        format_amount(output_total),
    ]));
    let (fee, feerate, feerate_estimated) = psbt.fee();

    let est = if feerate_estimated { "(est.)" } else { "" };
    table.add_row(Row::new(vec![
        "fee",
        &format!("{:.3} sats/vb {}", feerate.as_sat_vb(), est),
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
        || read_yn(&format!(
            "This is the transaction that will be broadcast.\n{}Ok",
            display_psbt(network, &psbt)
        ))
    {
        let tx = psbt.extract_tx();

        if print_tx {
            Ok((
                CmdOutput::EmphasisedItem {
                    main: (
                        "tx",
                        Cell::String(crate::hex::encode(&encode::serialize(&tx))),
                    ),
                    other: vec![],
                },
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
