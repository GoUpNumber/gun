mod bet;
mod config;
mod oracle;
mod setup;
mod wallet;
pub use bet::*;
pub use config::*;
pub use oracle::*;
pub use setup::*;
pub use wallet::*;

use crate::{
    config::GunSigner,
    database::{ProtocolKind, StringDescriptor},
    keychain::ProtocolSecret,
    signers::{PsbtDirSigner, PwSeedSigner, XKeySigner},
    wallet::GunWallet,
};
use anyhow::Context;
use bdk::{
    bitcoin::{
        consensus::encode,
        util::{
            address::Payload, bip32::ExtendedPrivKey, psbt::PartiallySignedTransaction as Psbt,
        },
        Address, Amount, Network, SignedAmount, Txid,
    },
    blockchain::{ConfigurableBlockchain, EsploraBlockchain},
    database::BatchDatabase,
    signer::Signer,
    sled,
    wallet::signer::SignerOrdering,
    KeychainKind, Wallet,
};
use std::sync::Arc;

use term_table::{row::Row, Table};

use crate::{
    chrono::NaiveDateTime,
    config::{Config, VersionedConfig},
    database::GunDatabase,
    keychain::Keychain,
    psbt_ext::PsbtFeeRate,
    FeeSpec, ValueChoice,
};
use anyhow::anyhow;
use std::{collections::HashMap, fs};

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

pub fn load_config(config_file: &std::path::Path) -> anyhow::Result<Config> {
    match config_file.exists() {
        true => {
            let json_config = fs::read_to_string(config_file)?;
            Ok(serde_json::from_str::<VersionedConfig>(&json_config)
                .context("Perhaps you are trying to load an old config?")?
                .into())
        }
        false => return Err(anyhow!("missing config file at {}", config_file.display())),
    }
}

pub fn write_config(config_file: &std::path::Path, config: Config) -> anyhow::Result<()> {
    fs::write(
        config_file,
        serde_json::to_string_pretty(&config.into_versioned())
            .unwrap()
            .as_bytes(),
    )
    .context("writing config file")?;
    Ok(())
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

    let config = load_config(&wallet_dir.join("config.json")).context("loading configuration")?;
    let database = sled::open(wallet_dir.join("database.sled").to_str().unwrap())
        .context("opening database.sled")?;

    let wallet_db = database
        .open_tree("wallet")
        .context("opening wallet tree")?;

    let esplora = EsploraBlockchain::from_config(config.blockchain_config())?;

    let gun_db = GunDatabase::new(database.open_tree("gun").context("opening gun db tree")?);

    let external = gun_db
        .get_entity::<StringDescriptor>(KeychainKind::External)?
        .ok_or(anyhow!(
            "external descriptor couldn't be retrieved from database"
        ))?;
    let internal = gun_db.get_entity::<StringDescriptor>(KeychainKind::Internal)?;

    let mut wallet = Wallet::new(
        &external.0,
        internal.as_ref().map(|x| &x.0),
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
                passphrase_fingerprint,
            } => {
                let file_path = wallet_dir.join("seed.txt");
                let seed_words = fs::read_to_string(&file_path).context("loading seed words")?;
                let mnemonic = Mnemonic::parse(&seed_words).map_err(|e| {
                    anyhow!(
                        "parsing seed phrase in '{}' failed: {}",
                        file_path.display(),
                        e
                    )
                })?;

                match passphrase_fingerprint {
                    Some(fingerprint) => Arc::new(PwSeedSigner {
                        mnemonic,
                        network: config.network,
                        master_fingerprint: *fingerprint,
                    }),
                    None => Arc::new(XKeySigner {
                        master_xkey: ExtendedPrivKey::new_master(
                            config.network,
                            &mnemonic.to_seed(""),
                        )
                        .unwrap(),
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

    let keychain = gun_db
        .get_entity::<ProtocolSecret>(ProtocolKind::Bet)?
        .map(Keychain::from);
    let gun_wallet = GunWallet::new(wallet, gun_db);

    Ok((gun_wallet, keychain, config))
}

pub fn load_wallet_db(wallet_dir: &std::path::Path) -> anyhow::Result<impl BatchDatabase> {
    let database = sled::open(wallet_dir.join("database.sled").to_str().unwrap())
        .context("opening database.sled")?;
    database.open_tree("wallet").context("opening wallet tree")
}

#[derive(Debug, Clone)]
pub struct TableData {
    col_names: Vec<String>,
    rows: Vec<Vec<Cell>>,
}

#[derive(serde::Serialize, Debug, Clone)]
#[serde(untagged)]
pub enum Cell {
    String(String),
    Amount(#[serde(with = "bdk::bitcoin::util::amount::serde::as_sat")] Amount),
    SignedAmount(#[serde(with = "bdk::bitcoin::util::amount::serde::as_sat")] SignedAmount),
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

pub fn format_signed_amount(amount: SignedAmount) -> String {
    if amount == SignedAmount::ZERO {
        "0".to_string()
    } else {
        let mut string = amount.to_string();
        string.insert(string.len() - 7, ' ');
        string.insert(string.len() - 11, ' ');
        let string = string.trim_end_matches(" BTC").trim_start_matches('-');
        if amount.is_negative() {
            format!("-{}", string)
        } else {
            format!("+{}", string)
        }
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

    pub fn maybe_string<T: core::fmt::Display>(t: Option<T>) -> Self {
        t.map(Self::string).unwrap_or(Cell::Empty)
    }

    pub fn datetime(dt: NaiveDateTime) -> Self {
        Self::DateTime(dt.timestamp() as u64)
    }

    pub fn render(self) -> String {
        use Cell::*;
        match self {
            String(string) => string,
            Amount(amount) => format_amount(amount),
            SignedAmount(amount) => format_signed_amount(amount),
            Int(integer) => integer.to_string(),
            Empty => "".into(),
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
            SignedAmount(amount) => amount.as_sat().to_string(),
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
            SignedAmount(amount) => serde_json::Value::Number(amount.as_sat().into()),
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

#[derive(Debug)]
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
                    if matches!(value, Cell::Amount(_) | Cell::SignedAmount(_)) {
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

fn ensure_not_watch_only(wallet: &GunWallet) -> anyhow::Result<()> {
    if wallet.is_watch_only() {
        Err(anyhow!(
            "You cannot do this command because this wallet is watch-only"
        ))
    } else {
        Ok(())
    }
}

#[macro_export]
macro_rules! item {
    ($($key:literal => $value:expr),+$(,)?) => {{
        let mut list = vec![];
        $(
            list.push(($key, $value));
        )*
        $crate::cmd::CmdOutput::Item(list)
    }}
}

#[macro_export]
macro_rules! eitem {
    ($main_key:literal => $main_value:expr $(,$key:literal => $value:expr)*$(,)?) => {{
        #[allow(unused_mut)]
        let mut list = vec![];
        $(
            list.push(($key, $value));
        )*
        $crate::cmd::CmdOutput::EmphasisedItem { main: ($main_key, $main_value), other: list }
    }}

#[macro_export]
macro_rules! elog {
    (@grinning_face $($tt:tt)*) => { eprint!("\u{2F600} "); eprintln!($($tt)*);};
    (@grinning_face_with_big_eyes $($tt:tt)*) => { eprint!("\u{1F603} "); eprintln!($($tt)*);};
    (@grinning_face_with_smiling_eyes $($tt:tt)*) => { eprint!("\u{1F604} "); eprintln!($($tt)*);};
    (@beaming_face_with_smiling_eyes $($tt:tt)*) => { eprint!("\u{1F601} "); eprintln!($($tt)*);};
    (@grinning_squinting_face $($tt:tt)*) => { eprint!("\u{1F606} "); eprintln!($($tt)*);};
    (@grinning_face_with_sweat $($tt:tt)*) => { eprint!("\u{1F605} "); eprintln!($($tt)*);};
    (@rolling_on_the_floor_laughing $($tt:tt)*) => { eprint!("\u{1F923} "); eprintln!($($tt)*);};
    (@face_with_tears_of_joy $($tt:tt)*) => { eprint!("\u{1F602} "); eprintln!($($tt)*);};
    (@slightly_smiling_face $($tt:tt)*) => { eprint!("\u{1F642} "); eprintln!($($tt)*);};
    (@upside_down_face $($tt:tt)*) => { eprint!("\u{1F643} "); eprintln!($($tt)*);};
    (@melting_face_$($tt:tt)*) => { eprint!("\u{1FAE0} "); eprintln!($($tt)*);};
    (@winking_face $($tt:tt)*) => { eprint!("\u{1F609} "); eprintln!($($tt)*);};
    (@smiling_face_with_smiling_eyes $($tt:tt)*) => { eprint!("\u{1F60A} "); eprintln!($($tt)*);};
    (@smiling_face_with_halo $($tt:tt)*) => { eprint!("\u{1F607} "); eprintln!($($tt)*);};
    (@smiling_face_with_hearts $($tt:tt)*) => { eprint!("\u{1F970} "); eprintln!($($tt)*);};
    (@smiling_face_with_heart-eyes $($tt:tt)*) => { eprint!("\u{1F60D} "); eprintln!($($tt)*);};
    (@star_struck $($tt:tt)*) => { eprint!("\u{1F929} "); eprintln!($($tt)*);};
    (@face_blowing_a_kiss $($tt:tt)*) => { eprint!("\u{1F618} "); eprintln!($($tt)*);};
    (@kissing_face $($tt:tt)*) => { eprint!("\u{1F617} "); eprintln!($($tt)*);};
    (@smiling_face $($tt:tt)*) => { eprint!("\u{263A} "); eprintln!($($tt)*);};
    (@kissing_face_with_closed_eyes $($tt:tt)*) => { eprint!("\u{1F61A} "); eprintln!($($tt)*);};
    (@kissing_face_with_smiling_eyes $($tt:tt)*) => { eprint!("\u{1F619} "); eprintln!($($tt)*);};
    (@smiling_face_with_tear $($tt:tt)*) => { eprint!("\u{1F972} "); eprintln!($($tt)*);};
    (@face_savoring_food $($tt:tt)*) => { eprint!("\u{1F60B} "); eprintln!($($tt)*);};
    (@face_with_tongue $($tt:tt)*) => { eprint!("\u{1F61B} "); eprintln!($($tt)*);};
    (@winking_face_with_tongue $($tt:tt)*) => { eprint!("\u{1F61C} "); eprintln!($($tt)*);};
    (@zany_face $($tt:tt)*) => { eprint!("\u{1F92A} "); eprintln!($($tt)*);};
    (@squinting_face_with_tongue $($tt:tt)*) => { eprint!("\u{1F61D} "); eprintln!($($tt)*);};
    (@money_mouth_face $($tt:tt)*) => { eprint!("\u{1F911} "); eprintln!($($tt)*);};
    (@smiling_face_with_open_hands $($tt:tt)*) => { eprint!("\u{1F917} "); eprintln!($($tt)*);};
    (@face_with_hand_over_mouth $($tt:tt)*) => { eprint!("\u{1F92D} "); eprintln!($($tt)*);};
    (@face_with_open_eyes_and_hand_over_mouth_ $($tt:tt)*) => { eprint!("\u{1FAE2} "); eprintln!($($tt)*);};
    (@face_with_peeking_eye_ $($tt:tt)*) => { eprint!("\u{1FAE3} "); eprintln!($($tt)*);};
    (@shushing_face $($tt:tt)*) => { eprint!("\u{1F92B} "); eprintln!($($tt)*);};
    (@thinking_face $($tt:tt)*) => { eprint!("\u{1F914} "); eprintln!($($tt)*);};
    (@saluting_face_ $($tt:tt)*) => { eprint!("\u{1FAE1} "); eprintln!($($tt)*);};
    (@zipper_mouth_face $($tt:tt)*) => { eprint!("\u{1F910} "); eprintln!($($tt)*);};
    (@face_with_raised_eyebrow $($tt:tt)*) => { eprint!("\u{1F928} "); eprintln!($($tt)*);};
    (@neutral_face $($tt:tt)*) => { eprint!("\u{1F610} "); eprintln!($($tt)*);};
    (@expressionless_face $($tt:tt)*) => { eprint!("\u{1F611} "); eprintln!($($tt)*);};
    (@face_without_mouth $($tt:tt)*) => { eprint!("\u{1F636} "); eprintln!($($tt)*);};
    (@dotted_line_face_ $($tt:tt)*) => { eprint!("\u{1FAE5} "); eprintln!($($tt)*);};
    (@face_in_clouds $($tt:tt)*) => { eprint!("\u{1F636} "); eprintln!($($tt)*);};
    (@smirking_face $($tt:tt)*) => { eprint!("\u{1F60F} "); eprintln!($($tt)*);};
    (@unamused_face $($tt:tt)*) => { eprint!("\u{1F612} "); eprintln!($($tt)*);};
    (@face_with_rolling_eyes $($tt:tt)*) => { eprint!("\u{1F644} "); eprintln!($($tt)*);};
    (@grimacing_face $($tt:tt)*) => { eprint!("\u{1F62C} "); eprintln!($($tt)*);};
    (@face_exhaling $($tt:tt)*) => { eprint!("\u{1F62E} "); eprintln!($($tt)*);};
    (@lying_face $($tt:tt)*) => { eprint!("\u{1F925} "); eprintln!($($tt)*);};
    (@relieved_face $($tt:tt)*) => { eprint!("\u{1F60C} "); eprintln!($($tt)*);};
    (@pensive_face $($tt:tt)*) => { eprint!("\u{1F614} "); eprintln!($($tt)*);};
    (@sleepy_face $($tt:tt)*) => { eprint!("\u{1F62A} "); eprintln!($($tt)*);};
    (@drooling_face $($tt:tt)*) => { eprint!("\u{1F924} "); eprintln!($($tt)*);};
    (@sleeping_face $($tt:tt)*) => { eprint!("\u{1F634} "); eprintln!($($tt)*);};
    (@face_with_medical_mask $($tt:tt)*) => { eprint!("\u{1F637} "); eprintln!($($tt)*);};
    (@face_with_thermometer $($tt:tt)*) => { eprint!("\u{1F912} "); eprintln!($($tt)*);};
    (@face_with_head_bandage $($tt:tt)*) => { eprint!("\u{1F915} "); eprintln!($($tt)*);};
    (@nauseated_face $($tt:tt)*) => { eprint!("\u{1F922} "); eprintln!($($tt)*);};
    (@face_vomiting $($tt:tt)*) => { eprint!("\u{1F92E} "); eprintln!($($tt)*);};
    (@sneezing_face $($tt:tt)*) => { eprint!("\u{1F927} "); eprintln!($($tt)*);};
    (@hot_face $($tt:tt)*) => { eprint!("\u{1F975} "); eprintln!($($tt)*);};
    (@cold_face $($tt:tt)*) => { eprint!("\u{1F976} "); eprintln!($($tt)*);};
    (@woozy_face $($tt:tt)*) => { eprint!("\u{1F974} "); eprintln!($($tt)*);};
    (@face_with_crossed_out_eyes $($tt:tt)*) => { eprint!("\u{1F635} "); eprintln!($($tt)*);};
    (@face_with_spiral_eyes $($tt:tt)*) => { eprint!("\u{1F635} "); eprintln!($($tt)*);};
    (@exploding_head $($tt:tt)*) => { eprint!("\u{1F92F} "); eprintln!($($tt)*);};
    (@cowboy_hat_face $($tt:tt)*) => { eprint!("\u{1F920} "); eprintln!($($tt)*);};
    (@partying_face $($tt:tt)*) => { eprint!("\u{1F973} "); eprintln!($($tt)*);};
    (@disguised_face $($tt:tt)*) => { eprint!("\u{1F978} "); eprintln!($($tt)*);};
    (@smiling_face_with_sunglasses $($tt:tt)*) => { eprint!("\u{1F60E} "); eprintln!($($tt)*);};
    (@nerd_face $($tt:tt)*) => { eprint!("\u{1F913} "); eprintln!($($tt)*);};
    (@face_with_monocle $($tt:tt)*) => { eprint!("\u{1F9D0} "); eprintln!($($tt)*);};
    (@confused_face $($tt:tt)*) => { eprint!("\u{1F615} "); eprintln!($($tt)*);};
    (@face_with_diagonal_mouth_ $($tt:tt)*) => { eprint!("\u{1FAE4} "); eprintln!($($tt)*);};
    (@worried_face $($tt:tt)*) => { eprint!("\u{1F61F} "); eprintln!($($tt)*);};
    (@slightly_frowning_face $($tt:tt)*) => { eprint!("\u{1F641} "); eprintln!($($tt)*);};
    (@frowning_face $($tt:tt)*) => { eprint!("\u{2639} "); eprintln!($($tt)*);};
    (@face_with_open_mouth $($tt:tt)*) => { eprint!("\u{1F62E} "); eprintln!($($tt)*);};
    (@hushed_face $($tt:tt)*) => { eprint!("\u{1F62F} "); eprintln!($($tt)*);};
    (@astonished_face $($tt:tt)*) => { eprint!("\u{1F632} "); eprintln!($($tt)*);};
    (@flushed_face $($tt:tt)*) => { eprint!("\u{1F633} "); eprintln!($($tt)*);};
    (@pleading_face $($tt:tt)*) => { eprint!("\u{1F97A} "); eprintln!($($tt)*);};
    (@face_holding_back_tears_ $($tt:tt)*) => { eprint!("\u{1F979} "); eprintln!($($tt)*);};
    (@frowning_face_with_open_mouth $($tt:tt)*) => { eprint!("\u{1F626} "); eprintln!($($tt)*);};
    (@anguished_face $($tt:tt)*) => { eprint!("\u{1F627} "); eprintln!($($tt)*);};
    (@fearful_face $($tt:tt)*) => { eprint!("\u{1F628} "); eprintln!($($tt)*);};
    (@anxious_face_with_sweat $($tt:tt)*) => { eprint!("\u{1F630} "); eprintln!($($tt)*);};
    (@sad_but_relieved_face $($tt:tt)*) => { eprint!("\u{1F625} "); eprintln!($($tt)*);};
    (@crying_face $($tt:tt)*) => { eprint!("\u{1F622} "); eprintln!($($tt)*);};
    (@loudly_crying_face $($tt:tt)*) => { eprint!("\u{1F62D} "); eprintln!($($tt)*);};
    (@face_screaming_in_fear $($tt:tt)*) => { eprint!("\u{1F631} "); eprintln!($($tt)*);};
    (@confounded_face $($tt:tt)*) => { eprint!("\u{1F616} "); eprintln!($($tt)*);};
    (@persevering_face $($tt:tt)*) => { eprint!("\u{1F623} "); eprintln!($($tt)*);};
    (@disappointed_face $($tt:tt)*) => { eprint!("\u{1F61E} "); eprintln!($($tt)*);};
    (@downcast_face_with_sweat $($tt:tt)*) => { eprint!("\u{1F613} "); eprintln!($($tt)*);};
    (@weary_face $($tt:tt)*) => { eprint!("\u{1F629} "); eprintln!($($tt)*);};
    (@tired_face $($tt:tt)*) => { eprint!("\u{1F62B} "); eprintln!($($tt)*);};
    (@yawning_face $($tt:tt)*) => { eprint!("\u{1F971} "); eprintln!($($tt)*);};
    (@face_with_steam_from_nose $($tt:tt)*) => { eprint!("\u{1F624} "); eprintln!($($tt)*);};
    (@pouting_face $($tt:tt)*) => { eprint!("\u{1F621} "); eprintln!($($tt)*);};
    (@angry_face $($tt:tt)*) => { eprint!("\u{1F620} "); eprintln!($($tt)*);};
    (@face_with_symbols_on_mouth $($tt:tt)*) => { eprint!("\u{1F92C} "); eprintln!($($tt)*);};
    (@smiling_face_with_horns $($tt:tt)*) => { eprint!("\u{1F608} "); eprintln!($($tt)*);};
    (@angry_face_with_horns $($tt:tt)*) => { eprint!("\u{1F47F} "); eprintln!($($tt)*);};
    (@skull $($tt:tt)*) => { eprint!("\u{1F480} "); eprintln!($($tt)*);};
    (@skull_and_crossbones $($tt:tt)*) => { eprint!("\u{2620} "); eprintln!($($tt)*);};
    (@pile_of_poo $($tt:tt)*) => { eprint!("\u{1F4A9} "); eprintln!($($tt)*);};
    (@clown_face $($tt:tt)*) => { eprint!("\u{1F921} "); eprintln!($($tt)*);};
    (@ogre $($tt:tt)*) => { eprint!("\u{1F479} "); eprintln!($($tt)*);};
    (@goblin $($tt:tt)*) => { eprint!("\u{1F47A} "); eprintln!($($tt)*);};
    (@ghost $($tt:tt)*) => { eprint!("\u{1F47B} "); eprintln!($($tt)*);};
    (@alien $($tt:tt)*) => { eprint!("\u{1F47D} "); eprintln!($($tt)*);};
    (@alien_monster $($tt:tt)*) => { eprint!("\u{1F47E} "); eprintln!($($tt)*);};
    (@robot $($tt:tt)*) => { eprint!("\u{1F916} "); eprintln!($($tt)*);};
    (@grinning_cat $($tt:tt)*) => { eprint!("\u{1F63A} "); eprintln!($($tt)*);};
    (@grinning_cat_with_smiling_eyes $($tt:tt)*) => { eprint!("\u{1F638} "); eprintln!($($tt)*);};
    (@cat_with_tears_of_joy $($tt:tt)*) => { eprint!("\u{1F639} "); eprintln!($($tt)*);};
    (@smiling_cat_with_heart_eyes $($tt:tt)*) => { eprint!("\u{1F63B} "); eprintln!($($tt)*);};
    (@cat_with_wry_smile $($tt:tt)*) => { eprint!("\u{1F63C} "); eprintln!($($tt)*);};
    (@kissing_cat $($tt:tt)*) => { eprint!("\u{1F63D} "); eprintln!($($tt)*);};
    (@weary_cat $($tt:tt)*) => { eprint!("\u{1F640} "); eprintln!($($tt)*);};
    (@crying_cat $($tt:tt)*) => { eprint!("\u{1F63F} "); eprintln!($($tt)*);};
    (@pouting_cat $($tt:tt)*) => { eprint!("\u{1F63E} "); eprintln!($($tt)*);};
    (@see_no_evil_monkey $($tt:tt)*) => { eprint!("\u{1F648} "); eprintln!($($tt)*);};
    (@hear_no_evil_monkey $($tt:tt)*) => { eprint!("\u{1F649} "); eprintln!($($tt)*);};
    (@speak_no_evil_monkey $($tt:tt)*) => { eprint!("\u{1F64A} "); eprintln!($($tt)*);};
    (@kiss_mark $($tt:tt)*) => { eprint!("\u{1F48B} "); eprintln!($($tt)*);};
    (@love_letter $($tt:tt)*) => { eprint!("\u{1F48C} "); eprintln!($($tt)*);};
    (@heart_with_arrow $($tt:tt)*) => { eprint!("\u{1F498} "); eprintln!($($tt)*);};
    (@heart_with_ribbon $($tt:tt)*) => { eprint!("\u{1F49D} "); eprintln!($($tt)*);};
    (@sparkling_heart $($tt:tt)*) => { eprint!("\u{1F496} "); eprintln!($($tt)*);};
    (@growing_heart $($tt:tt)*) => { eprint!("\u{1F497} "); eprintln!($($tt)*);};
    (@beating_heart $($tt:tt)*) => { eprint!("\u{1F493} "); eprintln!($($tt)*);};
    (@revolving_hearts $($tt:tt)*) => { eprint!("\u{1F49E} "); eprintln!($($tt)*);};
    (@two_hearts $($tt:tt)*) => { eprint!("\u{1F495} "); eprintln!($($tt)*);};
    (@heart_decoration $($tt:tt)*) => { eprint!("\u{1F49F} "); eprintln!($($tt)*);};
    (@heart_exclamation $($tt:tt)*) => { eprint!("\u{2763} "); eprintln!($($tt)*);};
    (@broken_heart $($tt:tt)*) => { eprint!("\u{1F494} "); eprintln!($($tt)*);};
    (@heart_on_fire $($tt:tt)*) => { eprint!("\u{2764} "); eprintln!($($tt)*);};
    (@mending_heart $($tt:tt)*) => { eprint!("\u{2764} "); eprintln!($($tt)*);};
    (@red_heart $($tt:tt)*) => { eprint!("\u{2764} "); eprintln!($($tt)*);};
    (@orange_heart $($tt:tt)*) => { eprint!("\u{1F9E1} "); eprintln!($($tt)*);};
    (@yellow_heart $($tt:tt)*) => { eprint!("\u{1F49B} "); eprintln!($($tt)*);};
    (@green_heart $($tt:tt)*) => { eprint!("\u{1F49A} "); eprintln!($($tt)*);};
    (@blue_heart $($tt:tt)*) => { eprint!("\u{1F499} "); eprintln!($($tt)*);};
    (@purple_heart $($tt:tt)*) => { eprint!("\u{1F49C} "); eprintln!($($tt)*);};
    (@brown_heart $($tt:tt)*) => { eprint!("\u{1F90E} "); eprintln!($($tt)*);};
    (@black_heart $($tt:tt)*) => { eprint!("\u{1F5A4} "); eprintln!($($tt)*);};
    (@white_heart $($tt:tt)*) => { eprint!("\u{1F90D} "); eprintln!($($tt)*);};
    (@hundred_points $($tt:tt)*) => { eprint!("\u{1F4AF} "); eprintln!($($tt)*);};
    (@anger_symbol $($tt:tt)*) => { eprint!("\u{1F4A2} "); eprintln!($($tt)*);};
    (@collision $($tt:tt)*) => { eprint!("\u{1F4A5} "); eprintln!($($tt)*);};
    (@dizzy $($tt:tt)*) => { eprint!("\u{1F4AB} "); eprintln!($($tt)*);};
    (@sweat_droplets $($tt:tt)*) => { eprint!("\u{1F4A6} "); eprintln!($($tt)*);};
    (@dashing_away $($tt:tt)*) => { eprint!("\u{1F4A8} "); eprintln!($($tt)*);};
    (@hole $($tt:tt)*) => { eprint!("\u{1F573} "); eprintln!($($tt)*);};
    (@bomb $($tt:tt)*) => { eprint!("\u{1F4A3} "); eprintln!($($tt)*);};
    (@speech_balloon $($tt:tt)*) => { eprint!("\u{1F4AC} "); eprintln!($($tt)*);};
    (@eye_in_speech_bubble $($tt:tt)*) => { eprint!("\u{1F441} "); eprintln!($($tt)*);};
    (@left_speech_bubble $($tt:tt)*) => { eprint!("\u{1F5E8} "); eprintln!($($tt)*);};
    (@right_anger_bubble $($tt:tt)*) => { eprint!("\u{1F5EF} "); eprintln!($($tt)*);};
    (@thought_balloon $($tt:tt)*) => { eprint!("\u{1F4AD} "); eprintln!($($tt)*);};
    (@zzz $($tt:tt)*) => { eprint!("\u{1F4A4} "); eprintln!($($tt)*);};
    (@waving_hand $($tt:tt)*) => { eprint!("\u{1F44B} "); eprintln!($($tt)*);};
    (@raised_back_of_hand $($tt:tt)*) => { eprint!("\u{1F91A} "); eprintln!($($tt)*);};
    (@hand_with_fingers_splayed $($tt:tt)*) => { eprint!("\u{1F590} "); eprintln!($($tt)*);};
    (@raised_hand $($tt:tt)*) => { eprint!("\u{270B} "); eprintln!($($tt)*);};
    (@vulcan_salute $($tt:tt)*) => { eprint!("\u{1F596} "); eprintln!($($tt)*);};
    (@rightwards_hand_ $($tt:tt)*) => { eprint!("\u{1FAF1} "); eprintln!($($tt)*);};
    (@leftwards_hand_ $($tt:tt)*) => { eprint!("\u{1FAF2} "); eprintln!($($tt)*);};
    (@palm_down_hand_ $($tt:tt)*) => { eprint!("\u{1FAF3} "); eprintln!($($tt)*);};
    (@palm_up_hand_ $($tt:tt)*) => { eprint!("\u{1FAF4} "); eprintln!($($tt)*);};
    (@ok_hand $($tt:tt)*) => { eprint!("\u{1F44C} "); eprintln!($($tt)*);};
    (@pinched_fingers $($tt:tt)*) => { eprint!("\u{1F90C} "); eprintln!($($tt)*);};
    (@pinching_hand $($tt:tt)*) => { eprint!("\u{1F90F} "); eprintln!($($tt)*);};
    (@victory_hand $($tt:tt)*) => { eprint!("\u{270C} "); eprintln!($($tt)*);};
    (@crossed_fingers $($tt:tt)*) => { eprint!("\u{1F91E} "); eprintln!($($tt)*);};
    (@hand_with_index_finger_and_thumb_crossed_ $($tt:tt)*) => { eprint!("\u{1FAF0} "); eprintln!($($tt)*);};
    (@love_you_gesture $($tt:tt)*) => { eprint!("\u{1F91F} "); eprintln!($($tt)*);};
    (@sign_of_the_horns $($tt:tt)*) => { eprint!("\u{1F918} "); eprintln!($($tt)*);};
    (@call_me_hand $($tt:tt)*) => { eprint!("\u{1F919} "); eprintln!($($tt)*);};
    (@backhand_index_pointing_left $($tt:tt)*) => { eprint!("\u{1F448} "); eprintln!($($tt)*);};
    (@backhand_index_pointing_right $($tt:tt)*) => { eprint!("\u{1F449} "); eprintln!($($tt)*);};
    (@backhand_index_pointing_up $($tt:tt)*) => { eprint!("\u{1F446} "); eprintln!($($tt)*);};
    (@middle_finger $($tt:tt)*) => { eprint!("\u{1F595} "); eprintln!($($tt)*);};
    (@backhand_index_pointing_down $($tt:tt)*) => { eprint!("\u{1F447} "); eprintln!($($tt)*);};
    (@index_pointing_up $($tt:tt)*) => { eprint!("\u{261D} "); eprintln!($($tt)*);};
    (@index_pointing_at_the_viewer_ $($tt:tt)*) => { eprint!("\u{1FAF5} "); eprintln!($($tt)*);};
    (@thumbs_up $($tt:tt)*) => { eprint!("\u{1F44D} "); eprintln!($($tt)*);};
    (@thumbs_down $($tt:tt)*) => { eprint!("\u{1F44E} "); eprintln!($($tt)*);};
    (@raised_fist $($tt:tt)*) => { eprint!("\u{270A} "); eprintln!($($tt)*);};
    (@oncoming_fist $($tt:tt)*) => { eprint!("\u{1F44A} "); eprintln!($($tt)*);};
    (@left_facing_fist $($tt:tt)*) => { eprint!("\u{1F91B} "); eprintln!($($tt)*);};
    (@right_facing_fist $($tt:tt)*) => { eprint!("\u{1F91C} "); eprintln!($($tt)*);};
    (@clapping_hands $($tt:tt)*) => { eprint!("\u{1F44F} "); eprintln!($($tt)*);};
    (@raising_hands $($tt:tt)*) => { eprint!("\u{1F64C} "); eprintln!($($tt)*);};
    (@heart_hands_ $($tt:tt)*) => { eprint!("\u{1FAF6} "); eprintln!($($tt)*);};
    (@open_hands $($tt:tt)*) => { eprint!("\u{1F450} "); eprintln!($($tt)*);};
    (@palms_up_together $($tt:tt)*) => { eprint!("\u{1F932} "); eprintln!($($tt)*);};
    (@handshake $($tt:tt)*) => { eprint!("\u{1F91D} "); eprintln!($($tt)*);};
    (@folded_hands $($tt:tt)*) => { eprint!("\u{1F64F} "); eprintln!($($tt)*);};
    (@writing_hand $($tt:tt)*) => { eprint!("\u{270D} "); eprintln!($($tt)*);};
    (@nail_polish $($tt:tt)*) => { eprint!("\u{1F485} "); eprintln!($($tt)*);};
    (@selfie $($tt:tt)*) => { eprint!("\u{1F933} "); eprintln!($($tt)*);};
    (@flexed_biceps $($tt:tt)*) => { eprint!("\u{1F4AA} "); eprintln!($($tt)*);};
    (@mechanical_arm $($tt:tt)*) => { eprint!("\u{1F9BE} "); eprintln!($($tt)*);};
    (@mechanical_leg $($tt:tt)*) => { eprint!("\u{1F9BF} "); eprintln!($($tt)*);};
    (@leg $($tt:tt)*) => { eprint!("\u{1F9B5} "); eprintln!($($tt)*);};
    (@foot $($tt:tt)*) => { eprint!("\u{1F9B6} "); eprintln!($($tt)*);};
    (@ear $($tt:tt)*) => { eprint!("\u{1F442} "); eprintln!($($tt)*);};
    (@ear_with_hearing_aid $($tt:tt)*) => { eprint!("\u{1F9BB} "); eprintln!($($tt)*);};
    (@nose $($tt:tt)*) => { eprint!("\u{1F443} "); eprintln!($($tt)*);};
    (@brain $($tt:tt)*) => { eprint!("\u{1F9E0} "); eprintln!($($tt)*);};
    (@anatomical_heart $($tt:tt)*) => { eprint!("\u{1FAC0} "); eprintln!($($tt)*);};
    (@lungs $($tt:tt)*) => { eprint!("\u{1FAC1} "); eprintln!($($tt)*);};
    (@tooth $($tt:tt)*) => { eprint!("\u{1F9B7} "); eprintln!($($tt)*);};
    (@bone $($tt:tt)*) => { eprint!("\u{1F9B4} "); eprintln!($($tt)*);};
    (@eyes $($tt:tt)*) => { eprint!("\u{1F440} "); eprintln!($($tt)*);};
    (@eye $($tt:tt)*) => { eprint!("\u{1F441} "); eprintln!($($tt)*);};
    (@tongue $($tt:tt)*) => { eprint!("\u{1F445} "); eprintln!($($tt)*);};
    (@mouth $($tt:tt)*) => { eprint!("\u{1F444} "); eprintln!($($tt)*);};
    (@biting_lip $($tt:tt)*) => { eprint!("\u{1FAE6} "); eprintln!($($tt)*);};
    (@baby $($tt:tt)*) => { eprint!("\u{1F476} "); eprintln!($($tt)*);};
    (@child $($tt:tt)*) => { eprint!("\u{1F9D2} "); eprintln!($($tt)*);};
    (@boy $($tt:tt)*) => { eprint!("\u{1F466} "); eprintln!($($tt)*);};
    (@girl $($tt:tt)*) => { eprint!("\u{1F467} "); eprintln!($($tt)*);};
    (@person $($tt:tt)*) => { eprint!("\u{1F9D1} "); eprintln!($($tt)*);};
    (@person_blond_hair $($tt:tt)*) => { eprint!("\u{1F471} "); eprintln!($($tt)*);};
    (@man $($tt:tt)*) => { eprint!("\u{1F468} "); eprintln!($($tt)*);};
    (@person_beard $($tt:tt)*) => { eprint!("\u{1F9D4} "); eprintln!($($tt)*);};
    (@man_beard $($tt:tt)*) => { eprint!("\u{1F9D4} "); eprintln!($($tt)*);};
    (@woman_beard $($tt:tt)*) => { eprint!("\u{1F9D4} "); eprintln!($($tt)*);};
    (@man_red_hair $($tt:tt)*) => { eprint!("\u{1F468} "); eprintln!($($tt)*);};
    (@man_curly_hair $($tt:tt)*) => { eprint!("\u{1F468} "); eprintln!($($tt)*);};
    (@man_white_hair $($tt:tt)*) => { eprint!("\u{1F468} "); eprintln!($($tt)*);};
    (@man_bald $($tt:tt)*) => { eprint!("\u{1F468} "); eprintln!($($tt)*);};
    (@woman $($tt:tt)*) => { eprint!("\u{1F469} "); eprintln!($($tt)*);};
    (@woman_red_hair $($tt:tt)*) => { eprint!("\u{1F469} "); eprintln!($($tt)*);};
    (@person_red_hair $($tt:tt)*) => { eprint!("\u{1F9D1} "); eprintln!($($tt)*);};
    (@woman_curly_hair $($tt:tt)*) => { eprint!("\u{1F469} "); eprintln!($($tt)*);};
    (@person_curly_hair $($tt:tt)*) => { eprint!("\u{1F9D1} "); eprintln!($($tt)*);};
    (@woman_white_hair $($tt:tt)*) => { eprint!("\u{1F469} "); eprintln!($($tt)*);};
    (@person_white_hair $($tt:tt)*) => { eprint!("\u{1F9D1} "); eprintln!($($tt)*);};
    (@woman_bald $($tt:tt)*) => { eprint!("\u{1F469} "); eprintln!($($tt)*);};
    (@person_bald $($tt:tt)*) => { eprint!("\u{1F9D1} "); eprintln!($($tt)*);};
    (@woman_blond_hair $($tt:tt)*) => { eprint!("\u{1F471} "); eprintln!($($tt)*);};
    (@man_blond_hair $($tt:tt)*) => { eprint!("\u{1F471} "); eprintln!($($tt)*);};
    (@older_person $($tt:tt)*) => { eprint!("\u{1F9D3} "); eprintln!($($tt)*);};
    (@old_man $($tt:tt)*) => { eprint!("\u{1F474} "); eprintln!($($tt)*);};
    (@old_woman $($tt:tt)*) => { eprint!("\u{1F475} "); eprintln!($($tt)*);};
    (@person_frowning $($tt:tt)*) => { eprint!("\u{1F64D} "); eprintln!($($tt)*);};
    (@man_frowning $($tt:tt)*) => { eprint!("\u{1F64D} "); eprintln!($($tt)*);};
    (@woman_frowning $($tt:tt)*) => { eprint!("\u{1F64D} "); eprintln!($($tt)*);};
    (@person_pouting $($tt:tt)*) => { eprint!("\u{1F64E} "); eprintln!($($tt)*);};
    (@man_pouting $($tt:tt)*) => { eprint!("\u{1F64E} "); eprintln!($($tt)*);};
    (@woman_pouting $($tt:tt)*) => { eprint!("\u{1F64E} "); eprintln!($($tt)*);};
    (@person_gesturing_no $($tt:tt)*) => { eprint!("\u{1F645} "); eprintln!($($tt)*);};
    (@man_gesturing_no $($tt:tt)*) => { eprint!("\u{1F645} "); eprintln!($($tt)*);};
    (@woman_gesturing_no $($tt:tt)*) => { eprint!("\u{1F645} "); eprintln!($($tt)*);};
    (@person_gesturing_ok $($tt:tt)*) => { eprint!("\u{1F646} "); eprintln!($($tt)*);};
    (@man_gesturing_ok $($tt:tt)*) => { eprint!("\u{1F646} "); eprintln!($($tt)*);};
    (@woman_gesturing_ok $($tt:tt)*) => { eprint!("\u{1F646} "); eprintln!($($tt)*);};
    (@person_tipping_hand $($tt:tt)*) => { eprint!("\u{1F481} "); eprintln!($($tt)*);};
    (@man_tipping_hand $($tt:tt)*) => { eprint!("\u{1F481} "); eprintln!($($tt)*);};
    (@woman_tipping_hand $($tt:tt)*) => { eprint!("\u{1F481} "); eprintln!($($tt)*);};
    (@person_raising_hand $($tt:tt)*) => { eprint!("\u{1F64B} "); eprintln!($($tt)*);};
    (@man_raising_hand $($tt:tt)*) => { eprint!("\u{1F64B} "); eprintln!($($tt)*);};
    (@woman_raising_hand $($tt:tt)*) => { eprint!("\u{1F64B} "); eprintln!($($tt)*);};
    (@deaf_person $($tt:tt)*) => { eprint!("\u{1F9CF} "); eprintln!($($tt)*);};
    (@deaf_man $($tt:tt)*) => { eprint!("\u{1F9CF} "); eprintln!($($tt)*);};
    (@deaf_woman $($tt:tt)*) => { eprint!("\u{1F9CF} "); eprintln!($($tt)*);};
    (@person_bowing $($tt:tt)*) => { eprint!("\u{1F647} "); eprintln!($($tt)*);};
    (@man_bowing $($tt:tt)*) => { eprint!("\u{1F647} "); eprintln!($($tt)*);};
    (@woman_bowing $($tt:tt)*) => { eprint!("\u{1F647} "); eprintln!($($tt)*);};
    (@person_facepalming $($tt:tt)*) => { eprint!("\u{1F926} "); eprintln!($($tt)*);};
    (@man_facepalming $($tt:tt)*) => { eprint!("\u{1F926} "); eprintln!($($tt)*);};
    (@woman_facepalming $($tt:tt)*) => { eprint!("\u{1F926} "); eprintln!($($tt)*);};
    (@person_shrugging $($tt:tt)*) => { eprint!("\u{1F937} "); eprintln!($($tt)*);};
    (@man_shrugging $($tt:tt)*) => { eprint!("\u{1F937} "); eprintln!($($tt)*);};
    (@woman_shrugging $($tt:tt)*) => { eprint!("\u{1F937} "); eprintln!($($tt)*);};
    (@health_worker $($tt:tt)*) => { eprint!("\u{1F9D1} "); eprintln!($($tt)*);};
    (@man_health_worker $($tt:tt)*) => { eprint!("\u{1F468} "); eprintln!($($tt)*);};
    (@woman_health_worker $($tt:tt)*) => { eprint!("\u{1F469} "); eprintln!($($tt)*);};
    (@student $($tt:tt)*) => { eprint!("\u{1F9D1} "); eprintln!($($tt)*);};
    (@man_student $($tt:tt)*) => { eprint!("\u{1F468} "); eprintln!($($tt)*);};
    (@woman_student $($tt:tt)*) => { eprint!("\u{1F469} "); eprintln!($($tt)*);};
    (@teacher $($tt:tt)*) => { eprint!("\u{1F9D1} "); eprintln!($($tt)*);};
    (@man_teacher $($tt:tt)*) => { eprint!("\u{1F468} "); eprintln!($($tt)*);};
    (@woman_teacher $($tt:tt)*) => { eprint!("\u{1F469} "); eprintln!($($tt)*);};
    (@judge $($tt:tt)*) => { eprint!("\u{1F9D1} "); eprintln!($($tt)*);};
    (@man_judge $($tt:tt)*) => { eprint!("\u{1F468} "); eprintln!($($tt)*);};
    (@woman_judge $($tt:tt)*) => { eprint!("\u{1F469} "); eprintln!($($tt)*);};
    (@farmer $($tt:tt)*) => { eprint!("\u{1F9D1} "); eprintln!($($tt)*);};
    (@man_farmer $($tt:tt)*) => { eprint!("\u{1F468} "); eprintln!($($tt)*);};
    (@woman_farmer $($tt:tt)*) => { eprint!("\u{1F469} "); eprintln!($($tt)*);};
    (@cook $($tt:tt)*) => { eprint!("\u{1F9D1} "); eprintln!($($tt)*);};
    (@man_cook $($tt:tt)*) => { eprint!("\u{1F468} "); eprintln!($($tt)*);};
    (@woman_cook $($tt:tt)*) => { eprint!("\u{1F469} "); eprintln!($($tt)*);};
    (@mechanic $($tt:tt)*) => { eprint!("\u{1F9D1} "); eprintln!($($tt)*);};
    (@man_mechanic $($tt:tt)*) => { eprint!("\u{1F468} "); eprintln!($($tt)*);};
    (@woman_mechanic $($tt:tt)*) => { eprint!("\u{1F469} "); eprintln!($($tt)*);};
    (@factory_worker $($tt:tt)*) => { eprint!("\u{1F9D1} "); eprintln!($($tt)*);};
    (@man_factory_worker $($tt:tt)*) => { eprint!("\u{1F468} "); eprintln!($($tt)*);};
    (@woman_factory_worker $($tt:tt)*) => { eprint!("\u{1F469} "); eprintln!($($tt)*);};
    (@office_worker $($tt:tt)*) => { eprint!("\u{1F9D1} "); eprintln!($($tt)*);};
    (@man_office_worker $($tt:tt)*) => { eprint!("\u{1F468} "); eprintln!($($tt)*);};
    (@woman_office_worker $($tt:tt)*) => { eprint!("\u{1F469} "); eprintln!($($tt)*);};
    (@scientist $($tt:tt)*) => { eprint!("\u{1F9D1} "); eprintln!($($tt)*);};
    (@man_scientist $($tt:tt)*) => { eprint!("\u{1F468} "); eprintln!($($tt)*);};
    (@woman_scientist $($tt:tt)*) => { eprint!("\u{1F469} "); eprintln!($($tt)*);};
    (@technologist $($tt:tt)*) => { eprint!("\u{1F9D1} "); eprintln!($($tt)*);};
    (@man_technologist $($tt:tt)*) => { eprint!("\u{1F468} "); eprintln!($($tt)*);};
    (@woman_technologist $($tt:tt)*) => { eprint!("\u{1F469} "); eprintln!($($tt)*);};
    (@singer $($tt:tt)*) => { eprint!("\u{1F9D1} "); eprintln!($($tt)*);};
    (@man_singer $($tt:tt)*) => { eprint!("\u{1F468} "); eprintln!($($tt)*);};
    (@woman_singer $($tt:tt)*) => { eprint!("\u{1F469} "); eprintln!($($tt)*);};
    (@artist $($tt:tt)*) => { eprint!("\u{1F9D1} "); eprintln!($($tt)*);};
    (@man_artist $($tt:tt)*) => { eprint!("\u{1F468} "); eprintln!($($tt)*);};
    (@woman_artist $($tt:tt)*) => { eprint!("\u{1F469} "); eprintln!($($tt)*);};
    (@pilot $($tt:tt)*) => { eprint!("\u{1F9D1} "); eprintln!($($tt)*);};
    (@man_pilot $($tt:tt)*) => { eprint!("\u{1F468} "); eprintln!($($tt)*);};
    (@woman_pilot $($tt:tt)*) => { eprint!("\u{1F469} "); eprintln!($($tt)*);};
    (@astronaut $($tt:tt)*) => { eprint!("\u{1F9D1} "); eprintln!($($tt)*);};
    (@man_astronaut $($tt:tt)*) => { eprint!("\u{1F468} "); eprintln!($($tt)*);};
    (@woman_astronaut $($tt:tt)*) => { eprint!("\u{1F469} "); eprintln!($($tt)*);};
    (@firefighter $($tt:tt)*) => { eprint!("\u{1F9D1} "); eprintln!($($tt)*);};
    (@man_firefighter $($tt:tt)*) => { eprint!("\u{1F468} "); eprintln!($($tt)*);};
    (@woman_firefighter $($tt:tt)*) => { eprint!("\u{1F469} "); eprintln!($($tt)*);};
    (@police_officer $($tt:tt)*) => { eprint!("\u{1F46E} "); eprintln!($($tt)*);};
    (@man_police_officer $($tt:tt)*) => { eprint!("\u{1F46E} "); eprintln!($($tt)*);};
    (@woman_police_officer $($tt:tt)*) => { eprint!("\u{1F46E} "); eprintln!($($tt)*);};
    (@detective $($tt:tt)*) => { eprint!("\u{1F575} "); eprintln!($($tt)*);};
    (@man_detective $($tt:tt)*) => { eprint!("\u{1F575} "); eprintln!($($tt)*);};
    (@woman_detective $($tt:tt)*) => { eprint!("\u{1F575} "); eprintln!($($tt)*);};
    (@guard $($tt:tt)*) => { eprint!("\u{1F482} "); eprintln!($($tt)*);};
    (@man_guard $($tt:tt)*) => { eprint!("\u{1F482} "); eprintln!($($tt)*);};
    (@woman_guard $($tt:tt)*) => { eprint!("\u{1F482} "); eprintln!($($tt)*);};
    (@ninja $($tt:tt)*) => { eprint!("\u{1F977} "); eprintln!($($tt)*);};
    (@construction_worker $($tt:tt)*) => { eprint!("\u{1F477} "); eprintln!($($tt)*);};
    (@man_construction_worker $($tt:tt)*) => { eprint!("\u{1F477} "); eprintln!($($tt)*);};
    (@woman_construction_worker $($tt:tt)*) => { eprint!("\u{1F477} "); eprintln!($($tt)*);};
    (@person_with_crown_ $($tt:tt)*) => { eprint!("\u{1FAC5} "); eprintln!($($tt)*);};
    (@prince $($tt:tt)*) => { eprint!("\u{1F934} "); eprintln!($($tt)*);};
    (@princess $($tt:tt)*) => { eprint!("\u{1F478} "); eprintln!($($tt)*);};
    (@person_wearing_turban $($tt:tt)*) => { eprint!("\u{1F473} "); eprintln!($($tt)*);};
    (@man_wearing_turban $($tt:tt)*) => { eprint!("\u{1F473} "); eprintln!($($tt)*);};
    (@woman_wearing_turban $($tt:tt)*) => { eprint!("\u{1F473} "); eprintln!($($tt)*);};
    (@person_with_skullcap $($tt:tt)*) => { eprint!("\u{1F472} "); eprintln!($($tt)*);};
    (@woman_with_headscarf $($tt:tt)*) => { eprint!("\u{1F9D5} "); eprintln!($($tt)*);};
    (@person_in_tuxedo $($tt:tt)*) => { eprint!("\u{1F935} "); eprintln!($($tt)*);};
    (@man_in_tuxedo $($tt:tt)*) => { eprint!("\u{1F935} "); eprintln!($($tt)*);};
    (@woman_in_tuxedo $($tt:tt)*) => { eprint!("\u{1F935} "); eprintln!($($tt)*);};
    (@person_with_veil $($tt:tt)*) => { eprint!("\u{1F470} "); eprintln!($($tt)*);};
    (@man_with_veil $($tt:tt)*) => { eprint!("\u{1F470} "); eprintln!($($tt)*);};
    (@woman_with_veil $($tt:tt)*) => { eprint!("\u{1F470} "); eprintln!($($tt)*);};
    (@pregnant_woman $($tt:tt)*) => { eprint!("\u{1F930} "); eprintln!($($tt)*);};
    (@pregnant_man_ $($tt:tt)*) => { eprint!("\u{1FAC3} "); eprintln!($($tt)*);};
    (@pregnant_person_ $($tt:tt)*) => { eprint!("\u{1FAC4} "); eprintln!($($tt)*);};
    (@breast_feeding $($tt:tt)*) => { eprint!("\u{1F931} "); eprintln!($($tt)*);};
    (@woman_feeding_baby $($tt:tt)*) => { eprint!("\u{1F469} "); eprintln!($($tt)*);};
    (@man_feeding_baby $($tt:tt)*) => { eprint!("\u{1F468} "); eprintln!($($tt)*);};
    (@person_feeding_baby $($tt:tt)*) => { eprint!("\u{1F9D1} "); eprintln!($($tt)*);};
    (@baby_angel $($tt:tt)*) => { eprint!("\u{1F47C} "); eprintln!($($tt)*);};
    (@Santa_Claus $($tt:tt)*) => { eprint!("\u{1F385} "); eprintln!($($tt)*);};
    (@Mrs._Claus $($tt:tt)*) => { eprint!("\u{1F936} "); eprintln!($($tt)*);};
    (@mx_claus $($tt:tt)*) => { eprint!("\u{1F9D1} "); eprintln!($($tt)*);};
    (@superhero $($tt:tt)*) => { eprint!("\u{1F9B8} "); eprintln!($($tt)*);};
    (@man_superhero $($tt:tt)*) => { eprint!("\u{1F9B8} "); eprintln!($($tt)*);};
    (@woman_superhero $($tt:tt)*) => { eprint!("\u{1F9B8} "); eprintln!($($tt)*);};
    (@supervillain $($tt:tt)*) => { eprint!("\u{1F9B9} "); eprintln!($($tt)*);};
    (@man_supervillain $($tt:tt)*) => { eprint!("\u{1F9B9} "); eprintln!($($tt)*);};
    (@woman_supervillain $($tt:tt)*) => { eprint!("\u{1F9B9} "); eprintln!($($tt)*);};
    (@mage $($tt:tt)*) => { eprint!("\u{1F9D9} "); eprintln!($($tt)*);};
    (@man_mage $($tt:tt)*) => { eprint!("\u{1F9D9} "); eprintln!($($tt)*);};
    (@woman_mage $($tt:tt)*) => { eprint!("\u{1F9D9} "); eprintln!($($tt)*);};
    (@fairy $($tt:tt)*) => { eprint!("\u{1F9DA} "); eprintln!($($tt)*);};
    (@man_fairy $($tt:tt)*) => { eprint!("\u{1F9DA} "); eprintln!($($tt)*);};
    (@woman_fairy $($tt:tt)*) => { eprint!("\u{1F9DA} "); eprintln!($($tt)*);};
    (@vampire $($tt:tt)*) => { eprint!("\u{1F9DB} "); eprintln!($($tt)*);};
    (@man_vampire $($tt:tt)*) => { eprint!("\u{1F9DB} "); eprintln!($($tt)*);};
    (@woman_vampire $($tt:tt)*) => { eprint!("\u{1F9DB} "); eprintln!($($tt)*);};
    (@merperson $($tt:tt)*) => { eprint!("\u{1F9DC} "); eprintln!($($tt)*);};
    (@merman $($tt:tt)*) => { eprint!("\u{1F9DC} "); eprintln!($($tt)*);};
    (@mermaid $($tt:tt)*) => { eprint!("\u{1F9DC} "); eprintln!($($tt)*);};
    (@elf $($tt:tt)*) => { eprint!("\u{1F9DD} "); eprintln!($($tt)*);};
    (@man_elf $($tt:tt)*) => { eprint!("\u{1F9DD} "); eprintln!($($tt)*);};
    (@woman_elf $($tt:tt)*) => { eprint!("\u{1F9DD} "); eprintln!($($tt)*);};
    (@genie $($tt:tt)*) => { eprint!("\u{1F9DE} "); eprintln!($($tt)*);};
    (@man_genie $($tt:tt)*) => { eprint!("\u{1F9DE} "); eprintln!($($tt)*);};
    (@woman_genie $($tt:tt)*) => { eprint!("\u{1F9DE} "); eprintln!($($tt)*);};
    (@zombie $($tt:tt)*) => { eprint!("\u{1F9DF} "); eprintln!($($tt)*);};
    (@man_zombie $($tt:tt)*) => { eprint!("\u{1F9DF} "); eprintln!($($tt)*);};
    (@woman_zombie $($tt:tt)*) => { eprint!("\u{1F9DF} "); eprintln!($($tt)*);};
    (@troll_ $($tt:tt)*) => { eprint!("\u{1F9CC} "); eprintln!($($tt)*);};
    (@person_getting_massage $($tt:tt)*) => { eprint!("\u{1F486} "); eprintln!($($tt)*);};
    (@man_getting_massage $($tt:tt)*) => { eprint!("\u{1F486} "); eprintln!($($tt)*);};
    (@woman_getting_massage $($tt:tt)*) => { eprint!("\u{1F486} "); eprintln!($($tt)*);};
    (@person_getting_haircut $($tt:tt)*) => { eprint!("\u{1F487} "); eprintln!($($tt)*);};
    (@man_getting_haircut $($tt:tt)*) => { eprint!("\u{1F487} "); eprintln!($($tt)*);};
    (@woman_getting_haircut $($tt:tt)*) => { eprint!("\u{1F487} "); eprintln!($($tt)*);};
    (@person_walking $($tt:tt)*) => { eprint!("\u{1F6B6} "); eprintln!($($tt)*);};
    (@man_walking $($tt:tt)*) => { eprint!("\u{1F6B6} "); eprintln!($($tt)*);};
    (@woman_walking $($tt:tt)*) => { eprint!("\u{1F6B6} "); eprintln!($($tt)*);};
    (@person_standing $($tt:tt)*) => { eprint!("\u{1F9CD} "); eprintln!($($tt)*);};
    (@man_standing $($tt:tt)*) => { eprint!("\u{1F9CD} "); eprintln!($($tt)*);};
    (@woman_standing $($tt:tt)*) => { eprint!("\u{1F9CD} "); eprintln!($($tt)*);};
    (@person_kneeling $($tt:tt)*) => { eprint!("\u{1F9CE} "); eprintln!($($tt)*);};
    (@man_kneeling $($tt:tt)*) => { eprint!("\u{1F9CE} "); eprintln!($($tt)*);};
    (@woman_kneeling $($tt:tt)*) => { eprint!("\u{1F9CE} "); eprintln!($($tt)*);};
    (@person_with_white_cane $($tt:tt)*) => { eprint!("\u{1F9D1} "); eprintln!($($tt)*);};
    (@man_with_white_cane $($tt:tt)*) => { eprint!("\u{1F468} "); eprintln!($($tt)*);};
    (@woman_with_white_cane $($tt:tt)*) => { eprint!("\u{1F469} "); eprintln!($($tt)*);};
    (@person_in_motorized_wheelchair $($tt:tt)*) => { eprint!("\u{1F9D1} "); eprintln!($($tt)*);};
    (@man_in_motorized_wheelchair $($tt:tt)*) => { eprint!("\u{1F468} "); eprintln!($($tt)*);};
    (@woman_in_motorized_wheelchair $($tt:tt)*) => { eprint!("\u{1F469} "); eprintln!($($tt)*);};
    (@person_in_manual_wheelchair $($tt:tt)*) => { eprint!("\u{1F9D1} "); eprintln!($($tt)*);};
    (@man_in_manual_wheelchair $($tt:tt)*) => { eprint!("\u{1F468} "); eprintln!($($tt)*);};
    (@woman_in_manual_wheelchair $($tt:tt)*) => { eprint!("\u{1F469} "); eprintln!($($tt)*);};
    (@person_running $($tt:tt)*) => { eprint!("\u{1F3C3} "); eprintln!($($tt)*);};
    (@man_running $($tt:tt)*) => { eprint!("\u{1F3C3} "); eprintln!($($tt)*);};
    (@woman_running $($tt:tt)*) => { eprint!("\u{1F3C3} "); eprintln!($($tt)*);};
    (@woman_dancing $($tt:tt)*) => { eprint!("\u{1F483} "); eprintln!($($tt)*);};
    (@man_dancing $($tt:tt)*) => { eprint!("\u{1F57A} "); eprintln!($($tt)*);};
    (@person_in_suit_levitating $($tt:tt)*) => { eprint!("\u{1F574} "); eprintln!($($tt)*);};
    (@people_with_bunny_ears $($tt:tt)*) => { eprint!("\u{1F46F} "); eprintln!($($tt)*);};
    (@men_with_bunny_ears $($tt:tt)*) => { eprint!("\u{1F46F} "); eprintln!($($tt)*);};
    (@women_with_bunny_ears $($tt:tt)*) => { eprint!("\u{1F46F} "); eprintln!($($tt)*);};
    (@person_in_steamy_room $($tt:tt)*) => { eprint!("\u{1F9D6} "); eprintln!($($tt)*);};
    (@man_in_steamy_room $($tt:tt)*) => { eprint!("\u{1F9D6} "); eprintln!($($tt)*);};
    (@woman_in_steamy_room $($tt:tt)*) => { eprint!("\u{1F9D6} "); eprintln!($($tt)*);};
    (@person_climbing $($tt:tt)*) => { eprint!("\u{1F9D7} "); eprintln!($($tt)*);};
    (@man_climbing $($tt:tt)*) => { eprint!("\u{1F9D7} "); eprintln!($($tt)*);};
    (@woman_climbing $($tt:tt)*) => { eprint!("\u{1F9D7} "); eprintln!($($tt)*);};
    (@person_fencing $($tt:tt)*) => { eprint!("\u{1F93A} "); eprintln!($($tt)*);};
    (@horse_racing $($tt:tt)*) => { eprint!("\u{1F3C7} "); eprintln!($($tt)*);};
    (@skier $($tt:tt)*) => { eprint!("\u{26F7} "); eprintln!($($tt)*);};
    (@snowboarder $($tt:tt)*) => { eprint!("\u{1F3C2} "); eprintln!($($tt)*);};
    (@person_golfing $($tt:tt)*) => { eprint!("\u{1F3CC} "); eprintln!($($tt)*);};
    (@man_golfing $($tt:tt)*) => { eprint!("\u{1F3CC} "); eprintln!($($tt)*);};
    (@woman_golfing $($tt:tt)*) => { eprint!("\u{1F3CC} "); eprintln!($($tt)*);};
    (@person_surfing $($tt:tt)*) => { eprint!("\u{1F3C4} "); eprintln!($($tt)*);};
    (@man_surfing $($tt:tt)*) => { eprint!("\u{1F3C4} "); eprintln!($($tt)*);};
    (@woman_surfing $($tt:tt)*) => { eprint!("\u{1F3C4} "); eprintln!($($tt)*);};
    (@person_rowing_boat $($tt:tt)*) => { eprint!("\u{1F6A3} "); eprintln!($($tt)*);};
    (@man_rowing_boat $($tt:tt)*) => { eprint!("\u{1F6A3} "); eprintln!($($tt)*);};
    (@woman_rowing_boat $($tt:tt)*) => { eprint!("\u{1F6A3} "); eprintln!($($tt)*);};
    (@person_swimming $($tt:tt)*) => { eprint!("\u{1F3CA} "); eprintln!($($tt)*);};
    (@man_swimming $($tt:tt)*) => { eprint!("\u{1F3CA} "); eprintln!($($tt)*);};
    (@woman_swimming $($tt:tt)*) => { eprint!("\u{1F3CA} "); eprintln!($($tt)*);};
    (@person_bouncing_ball $($tt:tt)*) => { eprint!("\u{26F9} "); eprintln!($($tt)*);};
    (@man_bouncing_ball $($tt:tt)*) => { eprint!("\u{26F9} "); eprintln!($($tt)*);};
    (@woman_bouncing_ball $($tt:tt)*) => { eprint!("\u{26F9} "); eprintln!($($tt)*);};
    (@person_lifting_weights $($tt:tt)*) => { eprint!("\u{1F3CB} "); eprintln!($($tt)*);};
    (@man_lifting_weights $($tt:tt)*) => { eprint!("\u{1F3CB} "); eprintln!($($tt)*);};
    (@woman_lifting_weights $($tt:tt)*) => { eprint!("\u{1F3CB} "); eprintln!($($tt)*);};
    (@person_biking $($tt:tt)*) => { eprint!("\u{1F6B4} "); eprintln!($($tt)*);};
    (@man_biking $($tt:tt)*) => { eprint!("\u{1F6B4} "); eprintln!($($tt)*);};
    (@woman_biking $($tt:tt)*) => { eprint!("\u{1F6B4} "); eprintln!($($tt)*);};
    (@person_mountain_biking $($tt:tt)*) => { eprint!("\u{1F6B5} "); eprintln!($($tt)*);};
    (@man_mountain_biking $($tt:tt)*) => { eprint!("\u{1F6B5} "); eprintln!($($tt)*);};
    (@woman_mountain_biking $($tt:tt)*) => { eprint!("\u{1F6B5} "); eprintln!($($tt)*);};
    (@person_cartwheeling $($tt:tt)*) => { eprint!("\u{1F938} "); eprintln!($($tt)*);};
    (@man_cartwheeling $($tt:tt)*) => { eprint!("\u{1F938} "); eprintln!($($tt)*);};
    (@woman_cartwheeling $($tt:tt)*) => { eprint!("\u{1F938} "); eprintln!($($tt)*);};
    (@people_wrestling $($tt:tt)*) => { eprint!("\u{1F93C} "); eprintln!($($tt)*);};
    (@men_wrestling $($tt:tt)*) => { eprint!("\u{1F93C} "); eprintln!($($tt)*);};
    (@women_wrestling $($tt:tt)*) => { eprint!("\u{1F93C} "); eprintln!($($tt)*);};
    (@person_playing_water_polo $($tt:tt)*) => { eprint!("\u{1F93D} "); eprintln!($($tt)*);};
    (@man_playing_water_polo $($tt:tt)*) => { eprint!("\u{1F93D} "); eprintln!($($tt)*);};
    (@woman_playing_water_polo $($tt:tt)*) => { eprint!("\u{1F93D} "); eprintln!($($tt)*);};
    (@person_playing_handball $($tt:tt)*) => { eprint!("\u{1F93E} "); eprintln!($($tt)*);};
    (@man_playing_handball $($tt:tt)*) => { eprint!("\u{1F93E} "); eprintln!($($tt)*);};
    (@woman_playing_handball $($tt:tt)*) => { eprint!("\u{1F93E} "); eprintln!($($tt)*);};
    (@person_juggling $($tt:tt)*) => { eprint!("\u{1F939} "); eprintln!($($tt)*);};
    (@man_juggling $($tt:tt)*) => { eprint!("\u{1F939} "); eprintln!($($tt)*);};
    (@woman_juggling $($tt:tt)*) => { eprint!("\u{1F939} "); eprintln!($($tt)*);};
    (@person_in_lotus_position $($tt:tt)*) => { eprint!("\u{1F9D8} "); eprintln!($($tt)*);};
    (@man_in_lotus_position $($tt:tt)*) => { eprint!("\u{1F9D8} "); eprintln!($($tt)*);};
    (@woman_in_lotus_position $($tt:tt)*) => { eprint!("\u{1F9D8} "); eprintln!($($tt)*);};
    (@person_taking_bath $($tt:tt)*) => { eprint!("\u{1F6C0} "); eprintln!($($tt)*);};
    (@person_in_bed $($tt:tt)*) => { eprint!("\u{1F6CC} "); eprintln!($($tt)*);};
    (@people_holding_hands $($tt:tt)*) => { eprint!("\u{1F9D1} "); eprintln!($($tt)*);};
    (@women_holding_hands $($tt:tt)*) => { eprint!("\u{1F46D} "); eprintln!($($tt)*);};
    (@woman_and_man_holding_hands $($tt:tt)*) => { eprint!("\u{1F46B} "); eprintln!($($tt)*);};
    (@men_holding_hands $($tt:tt)*) => { eprint!("\u{1F46C} "); eprintln!($($tt)*);};
    (@kiss $($tt:tt)*) => { eprint!("\u{1F48F} "); eprintln!($($tt)*);};
    (@speaking_head $($tt:tt)*) => { eprint!("\u{1F5E3} "); eprintln!($($tt)*);};
    (@bust_in_silhouette $($tt:tt)*) => { eprint!("\u{1F464} "); eprintln!($($tt)*);};
    (@busts_in_silhouette $($tt:tt)*) => { eprint!("\u{1F465} "); eprintln!($($tt)*);};
    (@people_hugging $($tt:tt)*) => { eprint!("\u{1FAC2} "); eprintln!($($tt)*);};
    (@footprints $($tt:tt)*) => { eprint!("\u{1F463} "); eprintln!($($tt)*);};
    (@red_hair $($tt:tt)*) => { eprint!("\u{1F9B0} "); eprintln!($($tt)*);};
    (@curly_hair $($tt:tt)*) => { eprint!("\u{1F9B1} "); eprintln!($($tt)*);};
    (@white_hair $($tt:tt)*) => { eprint!("\u{1F9B3} "); eprintln!($($tt)*);};
    (@bald $($tt:tt)*) => { eprint!("\u{1F9B2} "); eprintln!($($tt)*);};
    (@monkey_face $($tt:tt)*) => { eprint!("\u{1F435} "); eprintln!($($tt)*);};
    (@monkey $($tt:tt)*) => { eprint!("\u{1F412} "); eprintln!($($tt)*);};
    (@gorilla $($tt:tt)*) => { eprint!("\u{1F98D} "); eprintln!($($tt)*);};
    (@orangutan $($tt:tt)*) => { eprint!("\u{1F9A7} "); eprintln!($($tt)*);};
    (@dog_face $($tt:tt)*) => { eprint!("\u{1F436} "); eprintln!($($tt)*);};
    (@dog $($tt:tt)*) => { eprint!("\u{1F415} "); eprintln!($($tt)*);};
    (@guide_dog $($tt:tt)*) => { eprint!("\u{1F9AE} "); eprintln!($($tt)*);};
    (@service_dog $($tt:tt)*) => { eprint!("\u{1F415} "); eprintln!($($tt)*);};
    (@poodle $($tt:tt)*) => { eprint!("\u{1F429} "); eprintln!($($tt)*);};
    (@wolf $($tt:tt)*) => { eprint!("\u{1F43A} "); eprintln!($($tt)*);};
    (@fox $($tt:tt)*) => { eprint!("\u{1F98A} "); eprintln!($($tt)*);};
    (@raccoon $($tt:tt)*) => { eprint!("\u{1F99D} "); eprintln!($($tt)*);};
    (@cat_face $($tt:tt)*) => { eprint!("\u{1F431} "); eprintln!($($tt)*);};
    (@cat $($tt:tt)*) => { eprint!("\u{1F408} "); eprintln!($($tt)*);};
    (@black_cat $($tt:tt)*) => { eprint!("\u{1F408} "); eprintln!($($tt)*);};
    (@lion $($tt:tt)*) => { eprint!("\u{1F981} "); eprintln!($($tt)*);};
    (@tiger_face $($tt:tt)*) => { eprint!("\u{1F42F} "); eprintln!($($tt)*);};
    (@tiger $($tt:tt)*) => { eprint!("\u{1F405} "); eprintln!($($tt)*);};
    (@leopard $($tt:tt)*) => { eprint!("\u{1F406} "); eprintln!($($tt)*);};
    (@horse_face $($tt:tt)*) => { eprint!("\u{1F434} "); eprintln!($($tt)*);};
    (@horse $($tt:tt)*) => { eprint!("\u{1F40E} "); eprintln!($($tt)*);};
    (@unicorn $($tt:tt)*) => { eprint!("\u{1F984} "); eprintln!($($tt)*);};
    (@zebra $($tt:tt)*) => { eprint!("\u{1F993} "); eprintln!($($tt)*);};
    (@deer $($tt:tt)*) => { eprint!("\u{1F98C} "); eprintln!($($tt)*);};
    (@bison $($tt:tt)*) => { eprint!("\u{1F9AC} "); eprintln!($($tt)*);};
    (@cow_face $($tt:tt)*) => { eprint!("\u{1F42E} "); eprintln!($($tt)*);};
    (@ox $($tt:tt)*) => { eprint!("\u{1F402} "); eprintln!($($tt)*);};
    (@water_buffalo $($tt:tt)*) => { eprint!("\u{1F403} "); eprintln!($($tt)*);};
    (@cow $($tt:tt)*) => { eprint!("\u{1F404} "); eprintln!($($tt)*);};
    (@pig_face $($tt:tt)*) => { eprint!("\u{1F437} "); eprintln!($($tt)*);};
    (@pig $($tt:tt)*) => { eprint!("\u{1F416} "); eprintln!($($tt)*);};
    (@boar $($tt:tt)*) => { eprint!("\u{1F417} "); eprintln!($($tt)*);};
    (@pig_nose $($tt:tt)*) => { eprint!("\u{1F43D} "); eprintln!($($tt)*);};
    (@ram $($tt:tt)*) => { eprint!("\u{1F40F} "); eprintln!($($tt)*);};
    (@ewe $($tt:tt)*) => { eprint!("\u{1F411} "); eprintln!($($tt)*);};
    (@goat $($tt:tt)*) => { eprint!("\u{1F410} "); eprintln!($($tt)*);};
    (@camel $($tt:tt)*) => { eprint!("\u{1F42A} "); eprintln!($($tt)*);};
    (@two_hump_camel $($tt:tt)*) => { eprint!("\u{1F42B} "); eprintln!($($tt)*);};
    (@llama $($tt:tt)*) => { eprint!("\u{1F999} "); eprintln!($($tt)*);};
    (@giraffe $($tt:tt)*) => { eprint!("\u{1F992} "); eprintln!($($tt)*);};
    (@elephant $($tt:tt)*) => { eprint!("\u{1F418} "); eprintln!($($tt)*);};
    (@mammoth $($tt:tt)*) => { eprint!("\u{1F9A3} "); eprintln!($($tt)*);};
    (@rhinoceros $($tt:tt)*) => { eprint!("\u{1F98F} "); eprintln!($($tt)*);};
    (@hippopotamus $($tt:tt)*) => { eprint!("\u{1F99B} "); eprintln!($($tt)*);};
    (@mouse_face $($tt:tt)*) => { eprint!("\u{1F42D} "); eprintln!($($tt)*);};
    (@mouse $($tt:tt)*) => { eprint!("\u{1F401} "); eprintln!($($tt)*);};
    (@rat $($tt:tt)*) => { eprint!("\u{1F400} "); eprintln!($($tt)*);};
    (@hamster $($tt:tt)*) => { eprint!("\u{1F439} "); eprintln!($($tt)*);};
    (@rabbit_face $($tt:tt)*) => { eprint!("\u{1F430} "); eprintln!($($tt)*);};
    (@rabbit $($tt:tt)*) => { eprint!("\u{1F407} "); eprintln!($($tt)*);};
    (@chipmunk $($tt:tt)*) => { eprint!("\u{1F43F} "); eprintln!($($tt)*);};
    (@beaver $($tt:tt)*) => { eprint!("\u{1F9AB} "); eprintln!($($tt)*);};
    (@hedgehog $($tt:tt)*) => { eprint!("\u{1F994} "); eprintln!($($tt)*);};
    (@bat $($tt:tt)*) => { eprint!("\u{1F987} "); eprintln!($($tt)*);};
    (@bear $($tt:tt)*) => { eprint!("\u{1F43B} "); eprintln!($($tt)*);};
    (@polar_bear $($tt:tt)*) => { eprint!("\u{1F43B} "); eprintln!($($tt)*);};
    (@koala $($tt:tt)*) => { eprint!("\u{1F428} "); eprintln!($($tt)*);};
    (@panda $($tt:tt)*) => { eprint!("\u{1F43C} "); eprintln!($($tt)*);};
    (@sloth $($tt:tt)*) => { eprint!("\u{1F9A5} "); eprintln!($($tt)*);};
    (@otter $($tt:tt)*) => { eprint!("\u{1F9A6} "); eprintln!($($tt)*);};
    (@skunk $($tt:tt)*) => { eprint!("\u{1F9A8} "); eprintln!($($tt)*);};
    (@kangaroo $($tt:tt)*) => { eprint!("\u{1F998} "); eprintln!($($tt)*);};
    (@badger $($tt:tt)*) => { eprint!("\u{1F9A1} "); eprintln!($($tt)*);};
    (@paw_prints $($tt:tt)*) => { eprint!("\u{1F43E} "); eprintln!($($tt)*);};
    (@turkey $($tt:tt)*) => { eprint!("\u{1F983} "); eprintln!($($tt)*);};
    (@chicken $($tt:tt)*) => { eprint!("\u{1F414} "); eprintln!($($tt)*);};
    (@rooster $($tt:tt)*) => { eprint!("\u{1F413} "); eprintln!($($tt)*);};
    (@hatching_chick $($tt:tt)*) => { eprint!("\u{1F423} "); eprintln!($($tt)*);};
    (@baby_chick $($tt:tt)*) => { eprint!("\u{1F424} "); eprintln!($($tt)*);};
    (@front_facing_baby_chick $($tt:tt)*) => { eprint!("\u{1F425} "); eprintln!($($tt)*);};
    (@bird $($tt:tt)*) => { eprint!("\u{1F426} "); eprintln!($($tt)*);};
    (@penguin $($tt:tt)*) => { eprint!("\u{1F427} "); eprintln!($($tt)*);};
    (@dove $($tt:tt)*) => { eprint!("\u{1F54A} "); eprintln!($($tt)*);};
    (@eagle $($tt:tt)*) => { eprint!("\u{1F985} "); eprintln!($($tt)*);};
    (@duck $($tt:tt)*) => { eprint!("\u{1F986} "); eprintln!($($tt)*);};
    (@swan $($tt:tt)*) => { eprint!("\u{1F9A2} "); eprintln!($($tt)*);};
    (@owl $($tt:tt)*) => { eprint!("\u{1F989} "); eprintln!($($tt)*);};
    (@dodo $($tt:tt)*) => { eprint!("\u{1F9A4} "); eprintln!($($tt)*);};
    (@feather $($tt:tt)*) => { eprint!("\u{1FAB6} "); eprintln!($($tt)*);};
    (@flamingo $($tt:tt)*) => { eprint!("\u{1F9A9} "); eprintln!($($tt)*);};
    (@peacock $($tt:tt)*) => { eprint!("\u{1F99A} "); eprintln!($($tt)*);};
    (@parrot $($tt:tt)*) => { eprint!("\u{1F99C} "); eprintln!($($tt)*);};
    (@frog $($tt:tt)*) => { eprint!("\u{1F438} "); eprintln!($($tt)*);};
    (@crocodile $($tt:tt)*) => { eprint!("\u{1F40A} "); eprintln!($($tt)*);};
    (@turtle $($tt:tt)*) => { eprint!("\u{1F422} "); eprintln!($($tt)*);};
    (@lizard $($tt:tt)*) => { eprint!("\u{1F98E} "); eprintln!($($tt)*);};
    (@snake $($tt:tt)*) => { eprint!("\u{1F40D} "); eprintln!($($tt)*);};
    (@dragon_face $($tt:tt)*) => { eprint!("\u{1F432} "); eprintln!($($tt)*);};
    (@dragon $($tt:tt)*) => { eprint!("\u{1F409} "); eprintln!($($tt)*);};
    (@sauropod $($tt:tt)*) => { eprint!("\u{1F995} "); eprintln!($($tt)*);};
    (@t_rex $($tt:tt)*) => { eprint!("\u{1F996} "); eprintln!($($tt)*);};
    (@spouting_whale $($tt:tt)*) => { eprint!("\u{1F433} "); eprintln!($($tt)*);};
    (@whale $($tt:tt)*) => { eprint!("\u{1F40B} "); eprintln!($($tt)*);};
    (@dolphin $($tt:tt)*) => { eprint!("\u{1F42C} "); eprintln!($($tt)*);};
    (@seal $($tt:tt)*) => { eprint!("\u{1F9AD} "); eprintln!($($tt)*);};
    (@fish $($tt:tt)*) => { eprint!("\u{1F41F} "); eprintln!($($tt)*);};
    (@tropical_fish $($tt:tt)*) => { eprint!("\u{1F420} "); eprintln!($($tt)*);};
    (@blowfish $($tt:tt)*) => { eprint!("\u{1F421} "); eprintln!($($tt)*);};
    (@shark $($tt:tt)*) => { eprint!("\u{1F988} "); eprintln!($($tt)*);};
    (@octopus $($tt:tt)*) => { eprint!("\u{1F419} "); eprintln!($($tt)*);};
    (@spiral_shell $($tt:tt)*) => { eprint!("\u{1F41A} "); eprintln!($($tt)*);};
    (@coral_ $($tt:tt)*) => { eprint!("\u{1FAB8} "); eprintln!($($tt)*);};
    (@snail $($tt:tt)*) => { eprint!("\u{1F40C} "); eprintln!($($tt)*);};
    (@butterfly $($tt:tt)*) => { eprint!("\u{1F98B} "); eprintln!($($tt)*);};
    (@bug $($tt:tt)*) => { eprint!("\u{1F41B} "); eprintln!($($tt)*);};
    (@ant $($tt:tt)*) => { eprint!("\u{1F41C} "); eprintln!($($tt)*);};
    (@honeybee $($tt:tt)*) => { eprint!("\u{1F41D} "); eprintln!($($tt)*);};
    (@beetle $($tt:tt)*) => { eprint!("\u{1FAB2} "); eprintln!($($tt)*);};
    (@lady_beetle $($tt:tt)*) => { eprint!("\u{1F41E} "); eprintln!($($tt)*);};
    (@cricket $($tt:tt)*) => { eprint!("\u{1F997} "); eprintln!($($tt)*);};
    (@cockroach $($tt:tt)*) => { eprint!("\u{1FAB3} "); eprintln!($($tt)*);};
    (@spider $($tt:tt)*) => { eprint!("\u{1F577} "); eprintln!($($tt)*);};
    (@spider_web $($tt:tt)*) => { eprint!("\u{1F578} "); eprintln!($($tt)*);};
    (@scorpion $($tt:tt)*) => { eprint!("\u{1F982} "); eprintln!($($tt)*);};
    (@mosquito $($tt:tt)*) => { eprint!("\u{1F99F} "); eprintln!($($tt)*);};
    (@fly $($tt:tt)*) => { eprint!("\u{1FAB0} "); eprintln!($($tt)*);};
    (@worm $($tt:tt)*) => { eprint!("\u{1FAB1} "); eprintln!($($tt)*);};
    (@microbe $($tt:tt)*) => { eprint!("\u{1F9A0} "); eprintln!($($tt)*);};
    (@bouquet $($tt:tt)*) => { eprint!("\u{1F490} "); eprintln!($($tt)*);};
    (@cherry_blossom $($tt:tt)*) => { eprint!("\u{1F338} "); eprintln!($($tt)*);};
    (@white_flower $($tt:tt)*) => { eprint!("\u{1F4AE} "); eprintln!($($tt)*);};
    (@lotus_ $($tt:tt)*) => { eprint!("\u{1FAB7} "); eprintln!($($tt)*);};
    (@rosette $($tt:tt)*) => { eprint!("\u{1F3F5} "); eprintln!($($tt)*);};
    (@rose $($tt:tt)*) => { eprint!("\u{1F339} "); eprintln!($($tt)*);};
    (@wilted_flower $($tt:tt)*) => { eprint!("\u{1F940} "); eprintln!($($tt)*);};
    (@hibiscus $($tt:tt)*) => { eprint!("\u{1F33A} "); eprintln!($($tt)*);};
    (@sunflower $($tt:tt)*) => { eprint!("\u{1F33B} "); eprintln!($($tt)*);};
    (@blossom $($tt:tt)*) => { eprint!("\u{1F33C} "); eprintln!($($tt)*);};
    (@tulip $($tt:tt)*) => { eprint!("\u{1F337} "); eprintln!($($tt)*);};
    (@seedling $($tt:tt)*) => { eprint!("\u{1F331} "); eprintln!($($tt)*);};
    (@potted_plant $($tt:tt)*) => { eprint!("\u{1FAB4} "); eprintln!($($tt)*);};
    (@evergreen_tree $($tt:tt)*) => { eprint!("\u{1F332} "); eprintln!($($tt)*);};
    (@deciduous_tree $($tt:tt)*) => { eprint!("\u{1F333} "); eprintln!($($tt)*);};
    (@palm_tree $($tt:tt)*) => { eprint!("\u{1F334} "); eprintln!($($tt)*);};
    (@cactus $($tt:tt)*) => { eprint!("\u{1F335} "); eprintln!($($tt)*);};
    (@sheaf_of_rice $($tt:tt)*) => { eprint!("\u{1F33E} "); eprintln!($($tt)*);};
    (@herb $($tt:tt)*) => { eprint!("\u{1F33F} "); eprintln!($($tt)*);};
    (@shamrock $($tt:tt)*) => { eprint!("\u{2618} "); eprintln!($($tt)*);};
    (@four_leaf_clover $($tt:tt)*) => { eprint!("\u{1F340} "); eprintln!($($tt)*);};
    (@maple_leaf $($tt:tt)*) => { eprint!("\u{1F341} "); eprintln!($($tt)*);};
    (@fallen_leaf $($tt:tt)*) => { eprint!("\u{1F342} "); eprintln!($($tt)*);};
    (@leaf_fluttering_in_wind $($tt:tt)*) => { eprint!("\u{1F343} "); eprintln!($($tt)*);};
    (@empty_nest_ $($tt:tt)*) => { eprint!("\u{1FAB9} "); eprintln!($($tt)*);};
    (@nest_with_eggs_ $($tt:tt)*) => { eprint!("\u{1FABA} "); eprintln!($($tt)*);};
    (@grapes $($tt:tt)*) => { eprint!("\u{1F347} "); eprintln!($($tt)*);};
    (@melon $($tt:tt)*) => { eprint!("\u{1F348} "); eprintln!($($tt)*);};
    (@watermelon $($tt:tt)*) => { eprint!("\u{1F349} "); eprintln!($($tt)*);};
    (@tangerine $($tt:tt)*) => { eprint!("\u{1F34A} "); eprintln!($($tt)*);};
    (@lemon $($tt:tt)*) => { eprint!("\u{1F34B} "); eprintln!($($tt)*);};
    (@banana $($tt:tt)*) => { eprint!("\u{1F34C} "); eprintln!($($tt)*);};
    (@pineapple $($tt:tt)*) => { eprint!("\u{1F34D} "); eprintln!($($tt)*);};
    (@mango $($tt:tt)*) => { eprint!("\u{1F96D} "); eprintln!($($tt)*);};
    (@red_apple $($tt:tt)*) => { eprint!("\u{1F34E} "); eprintln!($($tt)*);};
    (@green_apple $($tt:tt)*) => { eprint!("\u{1F34F} "); eprintln!($($tt)*);};
    (@pear $($tt:tt)*) => { eprint!("\u{1F350} "); eprintln!($($tt)*);};
    (@peach $($tt:tt)*) => { eprint!("\u{1F351} "); eprintln!($($tt)*);};
    (@cherries $($tt:tt)*) => { eprint!("\u{1F352} "); eprintln!($($tt)*);};
    (@strawberry $($tt:tt)*) => { eprint!("\u{1F353} "); eprintln!($($tt)*);};
    (@blueberries $($tt:tt)*) => { eprint!("\u{1FAD0} "); eprintln!($($tt)*);};
    (@kiwi_fruit $($tt:tt)*) => { eprint!("\u{1F95D} "); eprintln!($($tt)*);};
    (@tomato $($tt:tt)*) => { eprint!("\u{1F345} "); eprintln!($($tt)*);};
    (@olive $($tt:tt)*) => { eprint!("\u{1FAD2} "); eprintln!($($tt)*);};
    (@coconut $($tt:tt)*) => { eprint!("\u{1F965} "); eprintln!($($tt)*);};
    (@avocado $($tt:tt)*) => { eprint!("\u{1F951} "); eprintln!($($tt)*);};
    (@eggplant $($tt:tt)*) => { eprint!("\u{1F346} "); eprintln!($($tt)*);};
    (@potato $($tt:tt)*) => { eprint!("\u{1F954} "); eprintln!($($tt)*);};
    (@carrot $($tt:tt)*) => { eprint!("\u{1F955} "); eprintln!($($tt)*);};
    (@ear_of_corn $($tt:tt)*) => { eprint!("\u{1F33D} "); eprintln!($($tt)*);};
    (@hot_pepper $($tt:tt)*) => { eprint!("\u{1F336} "); eprintln!($($tt)*);};
    (@bell_pepper $($tt:tt)*) => { eprint!("\u{1FAD1} "); eprintln!($($tt)*);};
    (@cucumber $($tt:tt)*) => { eprint!("\u{1F952} "); eprintln!($($tt)*);};
    (@leafy_green $($tt:tt)*) => { eprint!("\u{1F96C} "); eprintln!($($tt)*);};
    (@broccoli $($tt:tt)*) => { eprint!("\u{1F966} "); eprintln!($($tt)*);};
    (@garlic $($tt:tt)*) => { eprint!("\u{1F9C4} "); eprintln!($($tt)*);};
    (@onion $($tt:tt)*) => { eprint!("\u{1F9C5} "); eprintln!($($tt)*);};
    (@mushroom $($tt:tt)*) => { eprint!("\u{1F344} "); eprintln!($($tt)*);};
    (@peanuts $($tt:tt)*) => { eprint!("\u{1F95C} "); eprintln!($($tt)*);};
    (@beans_ $($tt:tt)*) => { eprint!("\u{1FAD8} "); eprintln!($($tt)*);};
    (@chestnut $($tt:tt)*) => { eprint!("\u{1F330} "); eprintln!($($tt)*);};
    (@bread $($tt:tt)*) => { eprint!("\u{1F35E} "); eprintln!($($tt)*);};
    (@croissant $($tt:tt)*) => { eprint!("\u{1F950} "); eprintln!($($tt)*);};
    (@baguette_bread $($tt:tt)*) => { eprint!("\u{1F956} "); eprintln!($($tt)*);};
    (@flatbread $($tt:tt)*) => { eprint!("\u{1FAD3} "); eprintln!($($tt)*);};
    (@pretzel $($tt:tt)*) => { eprint!("\u{1F968} "); eprintln!($($tt)*);};
    (@bagel $($tt:tt)*) => { eprint!("\u{1F96F} "); eprintln!($($tt)*);};
    (@pancakes $($tt:tt)*) => { eprint!("\u{1F95E} "); eprintln!($($tt)*);};
    (@waffle $($tt:tt)*) => { eprint!("\u{1F9C7} "); eprintln!($($tt)*);};
    (@cheese_wedge $($tt:tt)*) => { eprint!("\u{1F9C0} "); eprintln!($($tt)*);};
    (@meat_on_bone $($tt:tt)*) => { eprint!("\u{1F356} "); eprintln!($($tt)*);};
    (@poultry_leg $($tt:tt)*) => { eprint!("\u{1F357} "); eprintln!($($tt)*);};
    (@cut_of_meat $($tt:tt)*) => { eprint!("\u{1F969} "); eprintln!($($tt)*);};
    (@bacon $($tt:tt)*) => { eprint!("\u{1F953} "); eprintln!($($tt)*);};
    (@hamburger $($tt:tt)*) => { eprint!("\u{1F354} "); eprintln!($($tt)*);};
    (@french_fries $($tt:tt)*) => { eprint!("\u{1F35F} "); eprintln!($($tt)*);};
    (@pizza $($tt:tt)*) => { eprint!("\u{1F355} "); eprintln!($($tt)*);};
    (@hot_dog $($tt:tt)*) => { eprint!("\u{1F32D} "); eprintln!($($tt)*);};
    (@sandwich $($tt:tt)*) => { eprint!("\u{1F96A} "); eprintln!($($tt)*);};
    (@taco $($tt:tt)*) => { eprint!("\u{1F32E} "); eprintln!($($tt)*);};
    (@burrito $($tt:tt)*) => { eprint!("\u{1F32F} "); eprintln!($($tt)*);};
    (@tamale $($tt:tt)*) => { eprint!("\u{1FAD4} "); eprintln!($($tt)*);};
    (@stuffed_flatbread $($tt:tt)*) => { eprint!("\u{1F959} "); eprintln!($($tt)*);};
    (@falafel $($tt:tt)*) => { eprint!("\u{1F9C6} "); eprintln!($($tt)*);};
    (@egg $($tt:tt)*) => { eprint!("\u{1F95A} "); eprintln!($($tt)*);};
    (@cooking $($tt:tt)*) => { eprint!("\u{1F373} "); eprintln!($($tt)*);};
    (@shallow_pan_of_food $($tt:tt)*) => { eprint!("\u{1F958} "); eprintln!($($tt)*);};
    (@pot_of_food $($tt:tt)*) => { eprint!("\u{1F372} "); eprintln!($($tt)*);};
    (@fondue $($tt:tt)*) => { eprint!("\u{1FAD5} "); eprintln!($($tt)*);};
    (@bowl_with_spoon $($tt:tt)*) => { eprint!("\u{1F963} "); eprintln!($($tt)*);};
    (@green_salad $($tt:tt)*) => { eprint!("\u{1F957} "); eprintln!($($tt)*);};
    (@popcorn $($tt:tt)*) => { eprint!("\u{1F37F} "); eprintln!($($tt)*);};
    (@butter $($tt:tt)*) => { eprint!("\u{1F9C8} "); eprintln!($($tt)*);};
    (@salt $($tt:tt)*) => { eprint!("\u{1F9C2} "); eprintln!($($tt)*);};
    (@canned_food $($tt:tt)*) => { eprint!("\u{1F96B} "); eprintln!($($tt)*);};
    (@bento_box $($tt:tt)*) => { eprint!("\u{1F371} "); eprintln!($($tt)*);};
    (@rice_cracker $($tt:tt)*) => { eprint!("\u{1F358} "); eprintln!($($tt)*);};
    (@rice_ball $($tt:tt)*) => { eprint!("\u{1F359} "); eprintln!($($tt)*);};
    (@cooked_rice $($tt:tt)*) => { eprint!("\u{1F35A} "); eprintln!($($tt)*);};
    (@curry_rice $($tt:tt)*) => { eprint!("\u{1F35B} "); eprintln!($($tt)*);};
    (@steaming_bowl $($tt:tt)*) => { eprint!("\u{1F35C} "); eprintln!($($tt)*);};
    (@spaghetti $($tt:tt)*) => { eprint!("\u{1F35D} "); eprintln!($($tt)*);};
    (@roasted_sweet_potato $($tt:tt)*) => { eprint!("\u{1F360} "); eprintln!($($tt)*);};
    (@oden $($tt:tt)*) => { eprint!("\u{1F362} "); eprintln!($($tt)*);};
    (@sushi $($tt:tt)*) => { eprint!("\u{1F363} "); eprintln!($($tt)*);};
    (@fried_shrimp $($tt:tt)*) => { eprint!("\u{1F364} "); eprintln!($($tt)*);};
    (@fish_cake_with_swirl $($tt:tt)*) => { eprint!("\u{1F365} "); eprintln!($($tt)*);};
    (@moon_cake $($tt:tt)*) => { eprint!("\u{1F96E} "); eprintln!($($tt)*);};
    (@dango $($tt:tt)*) => { eprint!("\u{1F361} "); eprintln!($($tt)*);};
    (@dumpling $($tt:tt)*) => { eprint!("\u{1F95F} "); eprintln!($($tt)*);};
    (@fortune_cookie $($tt:tt)*) => { eprint!("\u{1F960} "); eprintln!($($tt)*);};
    (@takeout_box $($tt:tt)*) => { eprint!("\u{1F961} "); eprintln!($($tt)*);};
    (@crab $($tt:tt)*) => { eprint!("\u{1F980} "); eprintln!($($tt)*);};
    (@lobster $($tt:tt)*) => { eprint!("\u{1F99E} "); eprintln!($($tt)*);};
    (@shrimp $($tt:tt)*) => { eprint!("\u{1F990} "); eprintln!($($tt)*);};
    (@squid $($tt:tt)*) => { eprint!("\u{1F991} "); eprintln!($($tt)*);};
    (@oyster $($tt:tt)*) => { eprint!("\u{1F9AA} "); eprintln!($($tt)*);};
    (@soft_ice_cream $($tt:tt)*) => { eprint!("\u{1F366} "); eprintln!($($tt)*);};
    (@shaved_ice $($tt:tt)*) => { eprint!("\u{1F367} "); eprintln!($($tt)*);};
    (@ice_cream $($tt:tt)*) => { eprint!("\u{1F368} "); eprintln!($($tt)*);};
    (@doughnut $($tt:tt)*) => { eprint!("\u{1F369} "); eprintln!($($tt)*);};
    (@cookie $($tt:tt)*) => { eprint!("\u{1F36A} "); eprintln!($($tt)*);};
    (@birthday_cake $($tt:tt)*) => { eprint!("\u{1F382} "); eprintln!($($tt)*);};
    (@shortcake $($tt:tt)*) => { eprint!("\u{1F370} "); eprintln!($($tt)*);};
    (@cupcake $($tt:tt)*) => { eprint!("\u{1F9C1} "); eprintln!($($tt)*);};
    (@pie $($tt:tt)*) => { eprint!("\u{1F967} "); eprintln!($($tt)*);};
    (@chocolate_bar $($tt:tt)*) => { eprint!("\u{1F36B} "); eprintln!($($tt)*);};
    (@candy $($tt:tt)*) => { eprint!("\u{1F36C} "); eprintln!($($tt)*);};
    (@lollipop $($tt:tt)*) => { eprint!("\u{1F36D} "); eprintln!($($tt)*);};
    (@custard $($tt:tt)*) => { eprint!("\u{1F36E} "); eprintln!($($tt)*);};
    (@honey_pot $($tt:tt)*) => { eprint!("\u{1F36F} "); eprintln!($($tt)*);};
    (@baby_bottle $($tt:tt)*) => { eprint!("\u{1F37C} "); eprintln!($($tt)*);};
    (@glass_of_milk $($tt:tt)*) => { eprint!("\u{1F95B} "); eprintln!($($tt)*);};
    (@hot_beverage $($tt:tt)*) => { eprint!("\u{2615} "); eprintln!($($tt)*);};
    (@teapot $($tt:tt)*) => { eprint!("\u{1FAD6} "); eprintln!($($tt)*);};
    (@teacup_without_handle $($tt:tt)*) => { eprint!("\u{1F375} "); eprintln!($($tt)*);};
    (@sake $($tt:tt)*) => { eprint!("\u{1F376} "); eprintln!($($tt)*);};
    (@bottle_with_popping_cork $($tt:tt)*) => { eprint!("\u{1F37E} "); eprintln!($($tt)*);};
    (@wine_glass $($tt:tt)*) => { eprint!("\u{1F377} "); eprintln!($($tt)*);};
    (@cocktail_glass $($tt:tt)*) => { eprint!("\u{1F378} "); eprintln!($($tt)*);};
    (@tropical_drink $($tt:tt)*) => { eprint!("\u{1F379} "); eprintln!($($tt)*);};
    (@beer_mug $($tt:tt)*) => { eprint!("\u{1F37A} "); eprintln!($($tt)*);};
    (@clinking_beer_mugs $($tt:tt)*) => { eprint!("\u{1F37B} "); eprintln!($($tt)*);};
    (@clinking_glasses $($tt:tt)*) => { eprint!("\u{1F942} "); eprintln!($($tt)*);};
    (@tumbler_glass $($tt:tt)*) => { eprint!("\u{1F943} "); eprintln!($($tt)*);};
    (@pouring_liquid_ $($tt:tt)*) => { eprint!("\u{1FAD7} "); eprintln!($($tt)*);};
    (@cup_with_straw $($tt:tt)*) => { eprint!("\u{1F964} "); eprintln!($($tt)*);};
    (@bubble_tea $($tt:tt)*) => { eprint!("\u{1F9CB} "); eprintln!($($tt)*);};
    (@beverage_box $($tt:tt)*) => { eprint!("\u{1F9C3} "); eprintln!($($tt)*);};
    (@mate $($tt:tt)*) => { eprint!("\u{1F9C9} "); eprintln!($($tt)*);};
    (@ice $($tt:tt)*) => { eprint!("\u{1F9CA} "); eprintln!($($tt)*);};
    (@chopsticks $($tt:tt)*) => { eprint!("\u{1F962} "); eprintln!($($tt)*);};
    (@fork_and_knife_with_plate $($tt:tt)*) => { eprint!("\u{1F37D} "); eprintln!($($tt)*);};
    (@fork_and_knife $($tt:tt)*) => { eprint!("\u{1F374} "); eprintln!($($tt)*);};
    (@spoon $($tt:tt)*) => { eprint!("\u{1F944} "); eprintln!($($tt)*);};
    (@kitchen_knife $($tt:tt)*) => { eprint!("\u{1F52A} "); eprintln!($($tt)*);};
    (@jar $($tt:tt)*) => { eprint!("\u{1FAD9} "); eprintln!($($tt)*);};
    (@amphora $($tt:tt)*) => { eprint!("\u{1F3FA} "); eprintln!($($tt)*);};
    (@globe_showing_europe_africa $($tt:tt)*) => { eprint!("\u{1F30D} "); eprintln!($($tt)*);};
    (@globe_showing_americas $($tt:tt)*) => { eprint!("\u{1F30E} "); eprintln!($($tt)*);};
    (@globe_showing_asia_australia $($tt:tt)*) => { eprint!("\u{1F30F} "); eprintln!($($tt)*);};
    (@globe_with_meridians $($tt:tt)*) => { eprint!("\u{1F310} "); eprintln!($($tt)*);};
    (@world_map $($tt:tt)*) => { eprint!("\u{1F5FA} "); eprintln!($($tt)*);};
    (@map_of_japan $($tt:tt)*) => { eprint!("\u{1F5FE} "); eprintln!($($tt)*);};
    (@compass $($tt:tt)*) => { eprint!("\u{1F9ED} "); eprintln!($($tt)*);};
    (@snow_capped_mountain $($tt:tt)*) => { eprint!("\u{1F3D4} "); eprintln!($($tt)*);};
    (@mountain $($tt:tt)*) => { eprint!("\u{26F0} "); eprintln!($($tt)*);};
    (@volcano $($tt:tt)*) => { eprint!("\u{1F30B} "); eprintln!($($tt)*);};
    (@mount_fuji $($tt:tt)*) => { eprint!("\u{1F5FB} "); eprintln!($($tt)*);};
    (@camping $($tt:tt)*) => { eprint!("\u{1F3D5} "); eprintln!($($tt)*);};
    (@beach_with_umbrella $($tt:tt)*) => { eprint!("\u{1F3D6} "); eprintln!($($tt)*);};
    (@desert $($tt:tt)*) => { eprint!("\u{1F3DC} "); eprintln!($($tt)*);};
    (@desert_island $($tt:tt)*) => { eprint!("\u{1F3DD} "); eprintln!($($tt)*);};
    (@national_park $($tt:tt)*) => { eprint!("\u{1F3DE} "); eprintln!($($tt)*);};
    (@stadium $($tt:tt)*) => { eprint!("\u{1F3DF} "); eprintln!($($tt)*);};
    (@classical_building $($tt:tt)*) => { eprint!("\u{1F3DB} "); eprintln!($($tt)*);};
    (@building_construction $($tt:tt)*) => { eprint!("\u{1F3D7} "); eprintln!($($tt)*);};
    (@brick $($tt:tt)*) => { eprint!("\u{1F9F1} "); eprintln!($($tt)*);};
    (@rock $($tt:tt)*) => { eprint!("\u{1FAA8} "); eprintln!($($tt)*);};
    (@wood $($tt:tt)*) => { eprint!("\u{1FAB5} "); eprintln!($($tt)*);};
    (@hut $($tt:tt)*) => { eprint!("\u{1F6D6} "); eprintln!($($tt)*);};
    (@houses $($tt:tt)*) => { eprint!("\u{1F3D8} "); eprintln!($($tt)*);};
    (@derelict_house $($tt:tt)*) => { eprint!("\u{1F3DA} "); eprintln!($($tt)*);};
    (@house $($tt:tt)*) => { eprint!("\u{1F3E0} "); eprintln!($($tt)*);};
    (@house_with_garden $($tt:tt)*) => { eprint!("\u{1F3E1} "); eprintln!($($tt)*);};
    (@office_building $($tt:tt)*) => { eprint!("\u{1F3E2} "); eprintln!($($tt)*);};
    (@japanese_post_office $($tt:tt)*) => { eprint!("\u{1F3E3} "); eprintln!($($tt)*);};
    (@post_office $($tt:tt)*) => { eprint!("\u{1F3E4} "); eprintln!($($tt)*);};
    (@hospital $($tt:tt)*) => { eprint!("\u{1F3E5} "); eprintln!($($tt)*);};
    (@bank $($tt:tt)*) => { eprint!("\u{1F3E6} "); eprintln!($($tt)*);};
    (@hotel $($tt:tt)*) => { eprint!("\u{1F3E8} "); eprintln!($($tt)*);};
    (@love_hotel $($tt:tt)*) => { eprint!("\u{1F3E9} "); eprintln!($($tt)*);};
    (@convenience_store $($tt:tt)*) => { eprint!("\u{1F3EA} "); eprintln!($($tt)*);};
    (@school $($tt:tt)*) => { eprint!("\u{1F3EB} "); eprintln!($($tt)*);};
    (@department_store $($tt:tt)*) => { eprint!("\u{1F3EC} "); eprintln!($($tt)*);};
    (@factory $($tt:tt)*) => { eprint!("\u{1F3ED} "); eprintln!($($tt)*);};
    (@japanese_castle $($tt:tt)*) => { eprint!("\u{1F3EF} "); eprintln!($($tt)*);};
    (@castle $($tt:tt)*) => { eprint!("\u{1F3F0} "); eprintln!($($tt)*);};
    (@wedding $($tt:tt)*) => { eprint!("\u{1F492} "); eprintln!($($tt)*);};
    (@tokyo_tower $($tt:tt)*) => { eprint!("\u{1F5FC} "); eprintln!($($tt)*);};
    (@statue_of_liberty $($tt:tt)*) => { eprint!("\u{1F5FD} "); eprintln!($($tt)*);};
    (@church $($tt:tt)*) => { eprint!("\u{26EA} "); eprintln!($($tt)*);};
    (@mosque $($tt:tt)*) => { eprint!("\u{1F54C} "); eprintln!($($tt)*);};
    (@hindu_temple $($tt:tt)*) => { eprint!("\u{1F6D5} "); eprintln!($($tt)*);};
    (@synagogue $($tt:tt)*) => { eprint!("\u{1F54D} "); eprintln!($($tt)*);};
    (@shinto_shrine $($tt:tt)*) => { eprint!("\u{26E9} "); eprintln!($($tt)*);};
    (@kaaba $($tt:tt)*) => { eprint!("\u{1F54B} "); eprintln!($($tt)*);};
    (@fountain $($tt:tt)*) => { eprint!("\u{26F2} "); eprintln!($($tt)*);};
    (@tent $($tt:tt)*) => { eprint!("\u{26FA} "); eprintln!($($tt)*);};
    (@foggy $($tt:tt)*) => { eprint!("\u{1F301} "); eprintln!($($tt)*);};
    (@night_with_stars $($tt:tt)*) => { eprint!("\u{1F303} "); eprintln!($($tt)*);};
    (@cityscape $($tt:tt)*) => { eprint!("\u{1F3D9} "); eprintln!($($tt)*);};
    (@sunrise_over_mountains $($tt:tt)*) => { eprint!("\u{1F304} "); eprintln!($($tt)*);};
    (@sunrise $($tt:tt)*) => { eprint!("\u{1F305} "); eprintln!($($tt)*);};
    (@cityscape_at_dusk $($tt:tt)*) => { eprint!("\u{1F306} "); eprintln!($($tt)*);};
    (@sunset $($tt:tt)*) => { eprint!("\u{1F307} "); eprintln!($($tt)*);};
    (@bridge_at_night $($tt:tt)*) => { eprint!("\u{1F309} "); eprintln!($($tt)*);};
    (@hot_springs $($tt:tt)*) => { eprint!("\u{2668} "); eprintln!($($tt)*);};
    (@carousel_horse $($tt:tt)*) => { eprint!("\u{1F3A0} "); eprintln!($($tt)*);};
    (@playground_slide_ $($tt:tt)*) => { eprint!("\u{1F6DD} "); eprintln!($($tt)*);};
    (@ferris_wheel $($tt:tt)*) => { eprint!("\u{1F3A1} "); eprintln!($($tt)*);};
    (@roller_coaster $($tt:tt)*) => { eprint!("\u{1F3A2} "); eprintln!($($tt)*);};
    (@barber_pole $($tt:tt)*) => { eprint!("\u{1F488} "); eprintln!($($tt)*);};
    (@circus_tent $($tt:tt)*) => { eprint!("\u{1F3AA} "); eprintln!($($tt)*);};
    (@locomotive $($tt:tt)*) => { eprint!("\u{1F682} "); eprintln!($($tt)*);};
    (@railway_car $($tt:tt)*) => { eprint!("\u{1F683} "); eprintln!($($tt)*);};
    (@high_speed_train $($tt:tt)*) => { eprint!("\u{1F684} "); eprintln!($($tt)*);};
    (@bullet_train $($tt:tt)*) => { eprint!("\u{1F685} "); eprintln!($($tt)*);};
    (@train $($tt:tt)*) => { eprint!("\u{1F686} "); eprintln!($($tt)*);};
    (@metro $($tt:tt)*) => { eprint!("\u{1F687} "); eprintln!($($tt)*);};
    (@light_rail $($tt:tt)*) => { eprint!("\u{1F688} "); eprintln!($($tt)*);};
    (@station $($tt:tt)*) => { eprint!("\u{1F689} "); eprintln!($($tt)*);};
    (@tram $($tt:tt)*) => { eprint!("\u{1F68A} "); eprintln!($($tt)*);};
    (@monorail $($tt:tt)*) => { eprint!("\u{1F69D} "); eprintln!($($tt)*);};
    (@mountain_railway $($tt:tt)*) => { eprint!("\u{1F69E} "); eprintln!($($tt)*);};
    (@tram_car $($tt:tt)*) => { eprint!("\u{1F68B} "); eprintln!($($tt)*);};
    (@bus $($tt:tt)*) => { eprint!("\u{1F68C} "); eprintln!($($tt)*);};
    (@oncoming_bus $($tt:tt)*) => { eprint!("\u{1F68D} "); eprintln!($($tt)*);};
    (@trolleybus $($tt:tt)*) => { eprint!("\u{1F68E} "); eprintln!($($tt)*);};
    (@minibus $($tt:tt)*) => { eprint!("\u{1F690} "); eprintln!($($tt)*);};
    (@ambulance $($tt:tt)*) => { eprint!("\u{1F691} "); eprintln!($($tt)*);};
    (@fire_engine $($tt:tt)*) => { eprint!("\u{1F692} "); eprintln!($($tt)*);};
    (@police_car $($tt:tt)*) => { eprint!("\u{1F693} "); eprintln!($($tt)*);};
    (@oncoming_police_car $($tt:tt)*) => { eprint!("\u{1F694} "); eprintln!($($tt)*);};
    (@taxi $($tt:tt)*) => { eprint!("\u{1F695} "); eprintln!($($tt)*);};
    (@oncoming_taxi $($tt:tt)*) => { eprint!("\u{1F696} "); eprintln!($($tt)*);};
    (@automobile $($tt:tt)*) => { eprint!("\u{1F697} "); eprintln!($($tt)*);};
    (@oncoming_automobile $($tt:tt)*) => { eprint!("\u{1F698} "); eprintln!($($tt)*);};
    (@sport_utility_vehicle $($tt:tt)*) => { eprint!("\u{1F699} "); eprintln!($($tt)*);};
    (@pickup_truck $($tt:tt)*) => { eprint!("\u{1F6FB} "); eprintln!($($tt)*);};
    (@delivery_truck $($tt:tt)*) => { eprint!("\u{1F69A} "); eprintln!($($tt)*);};
    (@articulated_lorry $($tt:tt)*) => { eprint!("\u{1F69B} "); eprintln!($($tt)*);};
    (@tractor $($tt:tt)*) => { eprint!("\u{1F69C} "); eprintln!($($tt)*);};
    (@racing_car $($tt:tt)*) => { eprint!("\u{1F3CE} "); eprintln!($($tt)*);};
    (@motorcycle $($tt:tt)*) => { eprint!("\u{1F3CD} "); eprintln!($($tt)*);};
    (@motor_scooter $($tt:tt)*) => { eprint!("\u{1F6F5} "); eprintln!($($tt)*);};
    (@manual_wheelchair $($tt:tt)*) => { eprint!("\u{1F9BD} "); eprintln!($($tt)*);};
    (@motorized_wheelchair $($tt:tt)*) => { eprint!("\u{1F9BC} "); eprintln!($($tt)*);};
    (@auto_rickshaw $($tt:tt)*) => { eprint!("\u{1F6FA} "); eprintln!($($tt)*);};
    (@bicycle $($tt:tt)*) => { eprint!("\u{1F6B2} "); eprintln!($($tt)*);};
    (@kick_scooter $($tt:tt)*) => { eprint!("\u{1F6F4} "); eprintln!($($tt)*);};
    (@skateboard $($tt:tt)*) => { eprint!("\u{1F6F9} "); eprintln!($($tt)*);};
    (@roller_skate $($tt:tt)*) => { eprint!("\u{1F6FC} "); eprintln!($($tt)*);};
    (@bus_stop $($tt:tt)*) => { eprint!("\u{1F68F} "); eprintln!($($tt)*);};
    (@motorway $($tt:tt)*) => { eprint!("\u{1F6E3} "); eprintln!($($tt)*);};
    (@railway_track $($tt:tt)*) => { eprint!("\u{1F6E4} "); eprintln!($($tt)*);};
    (@oil_drum $($tt:tt)*) => { eprint!("\u{1F6E2} "); eprintln!($($tt)*);};
    (@fuel_pump $($tt:tt)*) => { eprint!("\u{26FD} "); eprintln!($($tt)*);};
    (@wheel_ $($tt:tt)*) => { eprint!("\u{1F6DE} "); eprintln!($($tt)*);};
    (@police_car_light $($tt:tt)*) => { eprint!("\u{1F6A8} "); eprintln!($($tt)*);};
    (@horizontal_traffic_light $($tt:tt)*) => { eprint!("\u{1F6A5} "); eprintln!($($tt)*);};
    (@vertical_traffic_light $($tt:tt)*) => { eprint!("\u{1F6A6} "); eprintln!($($tt)*);};
    (@stop_sign $($tt:tt)*) => { eprint!("\u{1F6D1} "); eprintln!($($tt)*);};
    (@construction $($tt:tt)*) => { eprint!("\u{1F6A7} "); eprintln!($($tt)*);};
    (@anchor $($tt:tt)*) => { eprint!("\u{2693} "); eprintln!($($tt)*);};
    (@ring_buoy_ $($tt:tt)*) => { eprint!("\u{1F6DF} "); eprintln!($($tt)*);};
    (@sailboat $($tt:tt)*) => { eprint!("\u{26F5} "); eprintln!($($tt)*);};
    (@canoe $($tt:tt)*) => { eprint!("\u{1F6F6} "); eprintln!($($tt)*);};
    (@speedboat $($tt:tt)*) => { eprint!("\u{1F6A4} "); eprintln!($($tt)*);};
    (@passenger_ship $($tt:tt)*) => { eprint!("\u{1F6F3} "); eprintln!($($tt)*);};
    (@ferry $($tt:tt)*) => { eprint!("\u{26F4} "); eprintln!($($tt)*);};
    (@motor_boat $($tt:tt)*) => { eprint!("\u{1F6E5} "); eprintln!($($tt)*);};
    (@ship $($tt:tt)*) => { eprint!("\u{1F6A2} "); eprintln!($($tt)*);};
    (@airplane $($tt:tt)*) => { eprint!("\u{2708} "); eprintln!($($tt)*);};
    (@small_airplane $($tt:tt)*) => { eprint!("\u{1F6E9} "); eprintln!($($tt)*);};
    (@airplane_departure $($tt:tt)*) => { eprint!("\u{1F6EB} "); eprintln!($($tt)*);};
    (@airplane_arrival $($tt:tt)*) => { eprint!("\u{1F6EC} "); eprintln!($($tt)*);};
    (@parachute $($tt:tt)*) => { eprint!("\u{1FA82} "); eprintln!($($tt)*);};
    (@seat $($tt:tt)*) => { eprint!("\u{1F4BA} "); eprintln!($($tt)*);};
    (@helicopter $($tt:tt)*) => { eprint!("\u{1F681} "); eprintln!($($tt)*);};
    (@suspension_railway $($tt:tt)*) => { eprint!("\u{1F69F} "); eprintln!($($tt)*);};
    (@mountain_cableway $($tt:tt)*) => { eprint!("\u{1F6A0} "); eprintln!($($tt)*);};
    (@aerial_tramway $($tt:tt)*) => { eprint!("\u{1F6A1} "); eprintln!($($tt)*);};
    (@satellite $($tt:tt)*) => { eprint!("\u{1F6F0} "); eprintln!($($tt)*);};
    (@rocket $($tt:tt)*) => { eprint!("\u{1F680} "); eprintln!($($tt)*);};
    (@flying_saucer $($tt:tt)*) => { eprint!("\u{1F6F8} "); eprintln!($($tt)*);};
    (@bellhop_bell $($tt:tt)*) => { eprint!("\u{1F6CE} "); eprintln!($($tt)*);};
    (@luggage $($tt:tt)*) => { eprint!("\u{1F9F3} "); eprintln!($($tt)*);};
    (@hourglass_done $($tt:tt)*) => { eprint!("\u{231B} "); eprintln!($($tt)*);};
    (@hourglass_not_done $($tt:tt)*) => { eprint!("\u{23F3} "); eprintln!($($tt)*);};
    (@watch $($tt:tt)*) => { eprint!("\u{231A} "); eprintln!($($tt)*);};
    (@alarm_clock $($tt:tt)*) => { eprint!("\u{23F0} "); eprintln!($($tt)*);};
    (@stopwatch $($tt:tt)*) => { eprint!("\u{23F1} "); eprintln!($($tt)*);};
    (@timer_clock $($tt:tt)*) => { eprint!("\u{23F2} "); eprintln!($($tt)*);};
    (@mantelpiece_clock $($tt:tt)*) => { eprint!("\u{1F570} "); eprintln!($($tt)*);};
    (@eleven_thirty $($tt:tt)*) => { eprint!("\u{1F566} "); eprintln!($($tt)*);};
    (@new_moon $($tt:tt)*) => { eprint!("\u{1F311} "); eprintln!($($tt)*);};
    (@waxing_crescent_moon $($tt:tt)*) => { eprint!("\u{1F312} "); eprintln!($($tt)*);};
    (@first_quarter_moon $($tt:tt)*) => { eprint!("\u{1F313} "); eprintln!($($tt)*);};
    (@waxing_gibbous_moon $($tt:tt)*) => { eprint!("\u{1F314} "); eprintln!($($tt)*);};
    (@full_moon $($tt:tt)*) => { eprint!("\u{1F315} "); eprintln!($($tt)*);};
    (@waning_gibbous_moon $($tt:tt)*) => { eprint!("\u{1F316} "); eprintln!($($tt)*);};
    (@last_quarter_moon $($tt:tt)*) => { eprint!("\u{1F317} "); eprintln!($($tt)*);};
    (@waning_crescent_moon $($tt:tt)*) => { eprint!("\u{1F318} "); eprintln!($($tt)*);};
    (@crescent_moon $($tt:tt)*) => { eprint!("\u{1F319} "); eprintln!($($tt)*);};
    (@new_moon_face $($tt:tt)*) => { eprint!("\u{1F31A} "); eprintln!($($tt)*);};
    (@first_quarter_moon_face $($tt:tt)*) => { eprint!("\u{1F31B} "); eprintln!($($tt)*);};
    (@last_quarter_moon_face $($tt:tt)*) => { eprint!("\u{1F31C} "); eprintln!($($tt)*);};
    (@thermometer $($tt:tt)*) => { eprint!("\u{1F321} "); eprintln!($($tt)*);};
    (@sun $($tt:tt)*) => { eprint!("\u{2600} "); eprintln!($($tt)*);};
    (@full_moon_face $($tt:tt)*) => { eprint!("\u{1F31D} "); eprintln!($($tt)*);};
    (@sun_with_face $($tt:tt)*) => { eprint!("\u{1F31E} "); eprintln!($($tt)*);};
    (@ringed_planet $($tt:tt)*) => { eprint!("\u{1FA90} "); eprintln!($($tt)*);};
    (@star $($tt:tt)*) => { eprint!("\u{2B50} "); eprintln!($($tt)*);};
    (@glowing_star $($tt:tt)*) => { eprint!("\u{1F31F} "); eprintln!($($tt)*);};
    (@shooting_star $($tt:tt)*) => { eprint!("\u{1F320} "); eprintln!($($tt)*);};
    (@milky_way $($tt:tt)*) => { eprint!("\u{1F30C} "); eprintln!($($tt)*);};
    (@cloud $($tt:tt)*) => { eprint!("\u{2601} "); eprintln!($($tt)*);};
    (@sun_behind_cloud $($tt:tt)*) => { eprint!("\u{26C5} "); eprintln!($($tt)*);};
    (@cloud_with_lightning_and_rain $($tt:tt)*) => { eprint!("\u{26C8} "); eprintln!($($tt)*);};
    (@sun_behind_small_cloud $($tt:tt)*) => { eprint!("\u{1F324} "); eprintln!($($tt)*);};
    (@sun_behind_large_cloud $($tt:tt)*) => { eprint!("\u{1F325} "); eprintln!($($tt)*);};
    (@sun_behind_rain_cloud $($tt:tt)*) => { eprint!("\u{1F326} "); eprintln!($($tt)*);};
    (@cloud_with_rain $($tt:tt)*) => { eprint!("\u{1F327} "); eprintln!($($tt)*);};
    (@cloud_with_snow $($tt:tt)*) => { eprint!("\u{1F328} "); eprintln!($($tt)*);};
    (@cloud_with_lightning $($tt:tt)*) => { eprint!("\u{1F329} "); eprintln!($($tt)*);};
    (@tornado $($tt:tt)*) => { eprint!("\u{1F32A} "); eprintln!($($tt)*);};
    (@fog $($tt:tt)*) => { eprint!("\u{1F32B} "); eprintln!($($tt)*);};
    (@wind_face $($tt:tt)*) => { eprint!("\u{1F32C} "); eprintln!($($tt)*);};
    (@cyclone $($tt:tt)*) => { eprint!("\u{1F300} "); eprintln!($($tt)*);};
    (@rainbow $($tt:tt)*) => { eprint!("\u{1F308} "); eprintln!($($tt)*);};
    (@closed_umbrella $($tt:tt)*) => { eprint!("\u{1F302} "); eprintln!($($tt)*);};
    (@umbrella $($tt:tt)*) => { eprint!("\u{2602} "); eprintln!($($tt)*);};
    (@umbrella_with_rain_drops $($tt:tt)*) => { eprint!("\u{2614} "); eprintln!($($tt)*);};
    (@umbrella_on_ground $($tt:tt)*) => { eprint!("\u{26F1} "); eprintln!($($tt)*);};
    (@high_voltage $($tt:tt)*) => { eprint!("\u{26A1} "); eprintln!($($tt)*);};
    (@snowflake $($tt:tt)*) => { eprint!("\u{2744} "); eprintln!($($tt)*);};
    (@snowman $($tt:tt)*) => { eprint!("\u{2603} "); eprintln!($($tt)*);};
    (@snowman_without_snow $($tt:tt)*) => { eprint!("\u{26C4} "); eprintln!($($tt)*);};
    (@comet $($tt:tt)*) => { eprint!("\u{2604} "); eprintln!($($tt)*);};
    (@fire $($tt:tt)*) => { eprint!("\u{1F525} "); eprintln!($($tt)*);};
    (@droplet $($tt:tt)*) => { eprint!("\u{1F4A7} "); eprintln!($($tt)*);};
    (@water_wave $($tt:tt)*) => { eprint!("\u{1F30A} "); eprintln!($($tt)*);};
    (@jack_o_lantern $($tt:tt)*) => { eprint!("\u{1F383} "); eprintln!($($tt)*);};
    (@christmas_tree $($tt:tt)*) => { eprint!("\u{1F384} "); eprintln!($($tt)*);};
    (@fireworks $($tt:tt)*) => { eprint!("\u{1F386} "); eprintln!($($tt)*);};
    (@sparkler $($tt:tt)*) => { eprint!("\u{1F387} "); eprintln!($($tt)*);};
    (@firecracker $($tt:tt)*) => { eprint!("\u{1F9E8} "); eprintln!($($tt)*);};
    (@sparkles $($tt:tt)*) => { eprint!("\u{2728} "); eprintln!($($tt)*);};
    (@balloon $($tt:tt)*) => { eprint!("\u{1F388} "); eprintln!($($tt)*);};
    (@party_popper $($tt:tt)*) => { eprint!("\u{1F389} "); eprintln!($($tt)*);};
    (@confetti_ball $($tt:tt)*) => { eprint!("\u{1F38A} "); eprintln!($($tt)*);};
    (@tanabata_tree $($tt:tt)*) => { eprint!("\u{1F38B} "); eprintln!($($tt)*);};
    (@pine_decoration $($tt:tt)*) => { eprint!("\u{1F38D} "); eprintln!($($tt)*);};
    (@japanese_dolls $($tt:tt)*) => { eprint!("\u{1F38E} "); eprintln!($($tt)*);};
    (@carp_streamer $($tt:tt)*) => { eprint!("\u{1F38F} "); eprintln!($($tt)*);};
    (@wind_chime $($tt:tt)*) => { eprint!("\u{1F390} "); eprintln!($($tt)*);};
    (@moon_viewing_ceremony $($tt:tt)*) => { eprint!("\u{1F391} "); eprintln!($($tt)*);};
    (@red_envelope $($tt:tt)*) => { eprint!("\u{1F9E7} "); eprintln!($($tt)*);};
    (@ribbon $($tt:tt)*) => { eprint!("\u{1F380} "); eprintln!($($tt)*);};
    (@wrapped_gift $($tt:tt)*) => { eprint!("\u{1F381} "); eprintln!($($tt)*);};
    (@reminder_ribbon $($tt:tt)*) => { eprint!("\u{1F397} "); eprintln!($($tt)*);};
    (@admission_tickets $($tt:tt)*) => { eprint!("\u{1F39F} "); eprintln!($($tt)*);};
    (@ticket $($tt:tt)*) => { eprint!("\u{1F3AB} "); eprintln!($($tt)*);};
    (@military_medal $($tt:tt)*) => { eprint!("\u{1F396} "); eprintln!($($tt)*);};
    (@trophy $($tt:tt)*) => { eprint!("\u{1F3C6} "); eprintln!($($tt)*);};
    (@sports_medal $($tt:tt)*) => { eprint!("\u{1F3C5} "); eprintln!($($tt)*);};
    (@first_place_medal $($tt:tt)*) => { eprint!("\u{1F947} "); eprintln!($($tt)*);};
    (@second_place_medal $($tt:tt)*) => { eprint!("\u{1F948} "); eprintln!($($tt)*);};
    (@third_place_medal $($tt:tt)*) => { eprint!("\u{1F949} "); eprintln!($($tt)*);};
    (@soccer_ball $($tt:tt)*) => { eprint!("\u{26BD} "); eprintln!($($tt)*);};
    (@baseball $($tt:tt)*) => { eprint!("\u{26BE} "); eprintln!($($tt)*);};
    (@softball $($tt:tt)*) => { eprint!("\u{1F94E} "); eprintln!($($tt)*);};
    (@basketball $($tt:tt)*) => { eprint!("\u{1F3C0} "); eprintln!($($tt)*);};
    (@volleyball $($tt:tt)*) => { eprint!("\u{1F3D0} "); eprintln!($($tt)*);};
    (@american_football $($tt:tt)*) => { eprint!("\u{1F3C8} "); eprintln!($($tt)*);};
    (@rugby_football $($tt:tt)*) => { eprint!("\u{1F3C9} "); eprintln!($($tt)*);};
    (@tennis $($tt:tt)*) => { eprint!("\u{1F3BE} "); eprintln!($($tt)*);};
    (@flying_disc $($tt:tt)*) => { eprint!("\u{1F94F} "); eprintln!($($tt)*);};
    (@bowling $($tt:tt)*) => { eprint!("\u{1F3B3} "); eprintln!($($tt)*);};
    (@cricket_game $($tt:tt)*) => { eprint!("\u{1F3CF} "); eprintln!($($tt)*);};
    (@field_hockey $($tt:tt)*) => { eprint!("\u{1F3D1} "); eprintln!($($tt)*);};
    (@ice_hockey $($tt:tt)*) => { eprint!("\u{1F3D2} "); eprintln!($($tt)*);};
    (@lacrosse $($tt:tt)*) => { eprint!("\u{1F94D} "); eprintln!($($tt)*);};
    (@ping_pong $($tt:tt)*) => { eprint!("\u{1F3D3} "); eprintln!($($tt)*);};
    (@badminton $($tt:tt)*) => { eprint!("\u{1F3F8} "); eprintln!($($tt)*);};
    (@boxing_glove $($tt:tt)*) => { eprint!("\u{1F94A} "); eprintln!($($tt)*);};
    (@martial_arts_uniform $($tt:tt)*) => { eprint!("\u{1F94B} "); eprintln!($($tt)*);};
    (@goal_net $($tt:tt)*) => { eprint!("\u{1F945} "); eprintln!($($tt)*);};
    (@flag_in_hole $($tt:tt)*) => { eprint!("\u{26F3} "); eprintln!($($tt)*);};
    (@ice_skate $($tt:tt)*) => { eprint!("\u{26F8} "); eprintln!($($tt)*);};
    (@fishing_pole $($tt:tt)*) => { eprint!("\u{1F3A3} "); eprintln!($($tt)*);};
    (@diving_mask $($tt:tt)*) => { eprint!("\u{1F93F} "); eprintln!($($tt)*);};
    (@running_shirt $($tt:tt)*) => { eprint!("\u{1F3BD} "); eprintln!($($tt)*);};
    (@skis $($tt:tt)*) => { eprint!("\u{1F3BF} "); eprintln!($($tt)*);};
    (@sled $($tt:tt)*) => { eprint!("\u{1F6F7} "); eprintln!($($tt)*);};
    (@curling_stone $($tt:tt)*) => { eprint!("\u{1F94C} "); eprintln!($($tt)*);};
    (@bullseye $($tt:tt)*) => { eprint!("\u{1F3AF} "); eprintln!($($tt)*);};
    (@yo_yo $($tt:tt)*) => { eprint!("\u{1FA80} "); eprintln!($($tt)*);};
    (@kite $($tt:tt)*) => { eprint!("\u{1FA81} "); eprintln!($($tt)*);};
    (@pool_8_ball $($tt:tt)*) => { eprint!("\u{1F3B1} "); eprintln!($($tt)*);};
    (@crystal_ball $($tt:tt)*) => { eprint!("\u{1F52E} "); eprintln!($($tt)*);};
    (@magic_wand $($tt:tt)*) => { eprint!("\u{1FA84} "); eprintln!($($tt)*);};
    (@nazar_amulet $($tt:tt)*) => { eprint!("\u{1F9FF} "); eprintln!($($tt)*);};
    (@hamsa_ $($tt:tt)*) => { eprint!("\u{1FAAC} "); eprintln!($($tt)*);};
    (@video_game $($tt:tt)*) => { eprint!("\u{1F3AE} "); eprintln!($($tt)*);};
    (@joystick $($tt:tt)*) => { eprint!("\u{1F579} "); eprintln!($($tt)*);};
    (@slot_machine $($tt:tt)*) => { eprint!("\u{1F3B0} "); eprintln!($($tt)*);};
    (@game_die $($tt:tt)*) => { eprint!("\u{1F3B2} "); eprintln!($($tt)*);};
    (@puzzle_piece $($tt:tt)*) => { eprint!("\u{1F9E9} "); eprintln!($($tt)*);};
    (@teddy_bear $($tt:tt)*) => { eprint!("\u{1F9F8} "); eprintln!($($tt)*);};
    (@pinata $($tt:tt)*) => { eprint!("\u{1FA85} "); eprintln!($($tt)*);};
    (@mirror_ball_ $($tt:tt)*) => { eprint!("\u{1FAA9} "); eprintln!($($tt)*);};
    (@nesting_dolls $($tt:tt)*) => { eprint!("\u{1FA86} "); eprintln!($($tt)*);};
    (@spade_suit $($tt:tt)*) => { eprint!("\u{2660} "); eprintln!($($tt)*);};
    (@heart_suit $($tt:tt)*) => { eprint!("\u{2665} "); eprintln!($($tt)*);};
    (@diamond_suit $($tt:tt)*) => { eprint!("\u{2666} "); eprintln!($($tt)*);};
    (@club_suit $($tt:tt)*) => { eprint!("\u{2663} "); eprintln!($($tt)*);};
    (@chess_pawn $($tt:tt)*) => { eprint!("\u{265F} "); eprintln!($($tt)*);};
    (@joker $($tt:tt)*) => { eprint!("\u{1F0CF} "); eprintln!($($tt)*);};
    (@mahjong_red_dragon $($tt:tt)*) => { eprint!("\u{1F004} "); eprintln!($($tt)*);};
    (@flower_playing_cards $($tt:tt)*) => { eprint!("\u{1F3B4} "); eprintln!($($tt)*);};
    (@performing_arts $($tt:tt)*) => { eprint!("\u{1F3AD} "); eprintln!($($tt)*);};
    (@framed_picture $($tt:tt)*) => { eprint!("\u{1F5BC} "); eprintln!($($tt)*);};
    (@artist_palette $($tt:tt)*) => { eprint!("\u{1F3A8} "); eprintln!($($tt)*);};
    (@thread $($tt:tt)*) => { eprint!("\u{1F9F5} "); eprintln!($($tt)*);};
    (@sewing_needle $($tt:tt)*) => { eprint!("\u{1FAA1} "); eprintln!($($tt)*);};
    (@yarn $($tt:tt)*) => { eprint!("\u{1F9F6} "); eprintln!($($tt)*);};
    (@knot $($tt:tt)*) => { eprint!("\u{1FAA2} "); eprintln!($($tt)*);};
    (@glasses $($tt:tt)*) => { eprint!("\u{1F453} "); eprintln!($($tt)*);};
    (@sunglasses $($tt:tt)*) => { eprint!("\u{1F576} "); eprintln!($($tt)*);};
    (@goggles $($tt:tt)*) => { eprint!("\u{1F97D} "); eprintln!($($tt)*);};
    (@lab_coat $($tt:tt)*) => { eprint!("\u{1F97C} "); eprintln!($($tt)*);};
    (@safety_vest $($tt:tt)*) => { eprint!("\u{1F9BA} "); eprintln!($($tt)*);};
    (@necktie $($tt:tt)*) => { eprint!("\u{1F454} "); eprintln!($($tt)*);};
    (@t_shirt $($tt:tt)*) => { eprint!("\u{1F455} "); eprintln!($($tt)*);};
    (@jeans $($tt:tt)*) => { eprint!("\u{1F456} "); eprintln!($($tt)*);};
    (@scarf $($tt:tt)*) => { eprint!("\u{1F9E3} "); eprintln!($($tt)*);};
    (@gloves $($tt:tt)*) => { eprint!("\u{1F9E4} "); eprintln!($($tt)*);};
    (@coat $($tt:tt)*) => { eprint!("\u{1F9E5} "); eprintln!($($tt)*);};
    (@socks $($tt:tt)*) => { eprint!("\u{1F9E6} "); eprintln!($($tt)*);};
    (@dress $($tt:tt)*) => { eprint!("\u{1F457} "); eprintln!($($tt)*);};
    (@kimono $($tt:tt)*) => { eprint!("\u{1F458} "); eprintln!($($tt)*);};
    (@sari $($tt:tt)*) => { eprint!("\u{1F97B} "); eprintln!($($tt)*);};
    (@one_piece_swimsuit $($tt:tt)*) => { eprint!("\u{1FA71} "); eprintln!($($tt)*);};
    (@briefs $($tt:tt)*) => { eprint!("\u{1FA72} "); eprintln!($($tt)*);};
    (@shorts $($tt:tt)*) => { eprint!("\u{1FA73} "); eprintln!($($tt)*);};
    (@bikini $($tt:tt)*) => { eprint!("\u{1F459} "); eprintln!($($tt)*);};
    (@womans_clothes $($tt:tt)*) => { eprint!("\u{1F45A} "); eprintln!($($tt)*);};
    (@purse $($tt:tt)*) => { eprint!("\u{1F45B} "); eprintln!($($tt)*);};
    (@handbag $($tt:tt)*) => { eprint!("\u{1F45C} "); eprintln!($($tt)*);};
    (@clutch_bag $($tt:tt)*) => { eprint!("\u{1F45D} "); eprintln!($($tt)*);};
    (@shopping_bags $($tt:tt)*) => { eprint!("\u{1F6CD} "); eprintln!($($tt)*);};
    (@backpack $($tt:tt)*) => { eprint!("\u{1F392} "); eprintln!($($tt)*);};
    (@thong_sandal $($tt:tt)*) => { eprint!("\u{1FA74} "); eprintln!($($tt)*);};
    (@mans_shoe $($tt:tt)*) => { eprint!("\u{1F45E} "); eprintln!($($tt)*);};
    (@running_shoe $($tt:tt)*) => { eprint!("\u{1F45F} "); eprintln!($($tt)*);};
    (@hiking_boot $($tt:tt)*) => { eprint!("\u{1F97E} "); eprintln!($($tt)*);};
    (@flat_shoe $($tt:tt)*) => { eprint!("\u{1F97F} "); eprintln!($($tt)*);};
    (@high_heeled_shoe $($tt:tt)*) => { eprint!("\u{1F460} "); eprintln!($($tt)*);};
    (@womans_sandal $($tt:tt)*) => { eprint!("\u{1F461} "); eprintln!($($tt)*);};
    (@ballet_shoes $($tt:tt)*) => { eprint!("\u{1FA70} "); eprintln!($($tt)*);};
    (@womans_boot $($tt:tt)*) => { eprint!("\u{1F462} "); eprintln!($($tt)*);};
    (@crown $($tt:tt)*) => { eprint!("\u{1F451} "); eprintln!($($tt)*);};
    (@womans_hat $($tt:tt)*) => { eprint!("\u{1F452} "); eprintln!($($tt)*);};
    (@top_hat $($tt:tt)*) => { eprint!("\u{1F3A9} "); eprintln!($($tt)*);};
    (@graduation_cap $($tt:tt)*) => { eprint!("\u{1F393} "); eprintln!($($tt)*);};
    (@billed_cap $($tt:tt)*) => { eprint!("\u{1F9E2} "); eprintln!($($tt)*);};
    (@military_helmet $($tt:tt)*) => { eprint!("\u{1FA96} "); eprintln!($($tt)*);};
    (@rescue_workers_helmet $($tt:tt)*) => { eprint!("\u{26D1} "); eprintln!($($tt)*);};
    (@prayer_beads $($tt:tt)*) => { eprint!("\u{1F4FF} "); eprintln!($($tt)*);};
    (@lipstick $($tt:tt)*) => { eprint!("\u{1F484} "); eprintln!($($tt)*);};
    (@ring $($tt:tt)*) => { eprint!("\u{1F48D} "); eprintln!($($tt)*);};
    (@gem_stone $($tt:tt)*) => { eprint!("\u{1F48E} "); eprintln!($($tt)*);};
    (@muted_speaker $($tt:tt)*) => { eprint!("\u{1F507} "); eprintln!($($tt)*);};
    (@speaker_low_volume $($tt:tt)*) => { eprint!("\u{1F508} "); eprintln!($($tt)*);};
    (@speaker_medium_volume $($tt:tt)*) => { eprint!("\u{1F509} "); eprintln!($($tt)*);};
    (@speaker_high_volume $($tt:tt)*) => { eprint!("\u{1F50A} "); eprintln!($($tt)*);};
    (@loudspeaker $($tt:tt)*) => { eprint!("\u{1F4E2} "); eprintln!($($tt)*);};
    (@megaphone $($tt:tt)*) => { eprint!("\u{1F4E3} "); eprintln!($($tt)*);};
    (@postal_horn $($tt:tt)*) => { eprint!("\u{1F4EF} "); eprintln!($($tt)*);};
    (@bell $($tt:tt)*) => { eprint!("\u{1F514} "); eprintln!($($tt)*);};
    (@bell_with_slash $($tt:tt)*) => { eprint!("\u{1F515} "); eprintln!($($tt)*);};
    (@musical_score $($tt:tt)*) => { eprint!("\u{1F3BC} "); eprintln!($($tt)*);};
    (@musical_note $($tt:tt)*) => { eprint!("\u{1F3B5} "); eprintln!($($tt)*);};
    (@musical_notes $($tt:tt)*) => { eprint!("\u{1F3B6} "); eprintln!($($tt)*);};
    (@studio_microphone $($tt:tt)*) => { eprint!("\u{1F399} "); eprintln!($($tt)*);};
    (@level_slider $($tt:tt)*) => { eprint!("\u{1F39A} "); eprintln!($($tt)*);};
    (@control_knobs $($tt:tt)*) => { eprint!("\u{1F39B} "); eprintln!($($tt)*);};
    (@microphone $($tt:tt)*) => { eprint!("\u{1F3A4} "); eprintln!($($tt)*);};
    (@headphone $($tt:tt)*) => { eprint!("\u{1F3A7} "); eprintln!($($tt)*);};
    (@radio $($tt:tt)*) => { eprint!("\u{1F4FB} "); eprintln!($($tt)*);};
    (@saxophone $($tt:tt)*) => { eprint!("\u{1F3B7} "); eprintln!($($tt)*);};
    (@accordion $($tt:tt)*) => { eprint!("\u{1FA97} "); eprintln!($($tt)*);};
    (@guitar $($tt:tt)*) => { eprint!("\u{1F3B8} "); eprintln!($($tt)*);};
    (@musical_keyboard $($tt:tt)*) => { eprint!("\u{1F3B9} "); eprintln!($($tt)*);};
    (@trumpet $($tt:tt)*) => { eprint!("\u{1F3BA} "); eprintln!($($tt)*);};
    (@violin $($tt:tt)*) => { eprint!("\u{1F3BB} "); eprintln!($($tt)*);};
    (@banjo $($tt:tt)*) => { eprint!("\u{1FA95} "); eprintln!($($tt)*);};
    (@drum $($tt:tt)*) => { eprint!("\u{1F941} "); eprintln!($($tt)*);};
    (@long_drum $($tt:tt)*) => { eprint!("\u{1FA98} "); eprintln!($($tt)*);};
    (@mobile_phone $($tt:tt)*) => { eprint!("\u{1F4F1} "); eprintln!($($tt)*);};
    (@mobile_phone_with_arrow $($tt:tt)*) => { eprint!("\u{1F4F2} "); eprintln!($($tt)*);};
    (@telephone $($tt:tt)*) => { eprint!("\u{260E} "); eprintln!($($tt)*);};
    (@telephone_receiver $($tt:tt)*) => { eprint!("\u{1F4DE} "); eprintln!($($tt)*);};
    (@pager $($tt:tt)*) => { eprint!("\u{1F4DF} "); eprintln!($($tt)*);};
    (@fax_machine $($tt:tt)*) => { eprint!("\u{1F4E0} "); eprintln!($($tt)*);};
    (@battery $($tt:tt)*) => { eprint!("\u{1F50B} "); eprintln!($($tt)*);};
    (@low_battery_ $($tt:tt)*) => { eprint!("\u{1FAAB} "); eprintln!($($tt)*);};
    (@electric_plug $($tt:tt)*) => { eprint!("\u{1F50C} "); eprintln!($($tt)*);};
    (@laptop $($tt:tt)*) => { eprint!("\u{1F4BB} "); eprintln!($($tt)*);};
    (@desktop_computer $($tt:tt)*) => { eprint!("\u{1F5A5} "); eprintln!($($tt)*);};
    (@printer $($tt:tt)*) => { eprint!("\u{1F5A8} "); eprintln!($($tt)*);};
    (@keyboard $($tt:tt)*) => { eprint!("\u{2328} "); eprintln!($($tt)*);};
    (@computer_mouse $($tt:tt)*) => { eprint!("\u{1F5B1} "); eprintln!($($tt)*);};
    (@trackball $($tt:tt)*) => { eprint!("\u{1F5B2} "); eprintln!($($tt)*);};
    (@computer_disk $($tt:tt)*) => { eprint!("\u{1F4BD} "); eprintln!($($tt)*);};
    (@floppy_disk $($tt:tt)*) => { eprint!("\u{1F4BE} "); eprintln!($($tt)*);};
    (@optical_disk $($tt:tt)*) => { eprint!("\u{1F4BF} "); eprintln!($($tt)*);};
    (@dvd $($tt:tt)*) => { eprint!("\u{1F4C0} "); eprintln!($($tt)*);};
    (@abacus $($tt:tt)*) => { eprint!("\u{1F9EE} "); eprintln!($($tt)*);};
    (@movie_camera $($tt:tt)*) => { eprint!("\u{1F3A5} "); eprintln!($($tt)*);};
    (@film_frames $($tt:tt)*) => { eprint!("\u{1F39E} "); eprintln!($($tt)*);};
    (@film_projector $($tt:tt)*) => { eprint!("\u{1F4FD} "); eprintln!($($tt)*);};
    (@clapper_board $($tt:tt)*) => { eprint!("\u{1F3AC} "); eprintln!($($tt)*);};
    (@television $($tt:tt)*) => { eprint!("\u{1F4FA} "); eprintln!($($tt)*);};
    (@camera $($tt:tt)*) => { eprint!("\u{1F4F7} "); eprintln!($($tt)*);};
    (@camera_with_flash $($tt:tt)*) => { eprint!("\u{1F4F8} "); eprintln!($($tt)*);};
    (@video_camera $($tt:tt)*) => { eprint!("\u{1F4F9} "); eprintln!($($tt)*);};
    (@videocassette $($tt:tt)*) => { eprint!("\u{1F4FC} "); eprintln!($($tt)*);};
    (@magnifying_glass_tilted_left $($tt:tt)*) => { eprint!("\u{1F50D} "); eprintln!($($tt)*);};
    (@magnifying_glass_tilted_right $($tt:tt)*) => { eprint!("\u{1F50E} "); eprintln!($($tt)*);};
    (@candle $($tt:tt)*) => { eprint!("\u{1F56F} "); eprintln!($($tt)*);};
    (@light_bulb $($tt:tt)*) => { eprint!("\u{1F4A1} "); eprintln!($($tt)*);};
    (@flashlight $($tt:tt)*) => { eprint!("\u{1F526} "); eprintln!($($tt)*);};
    (@red_paper_lantern $($tt:tt)*) => { eprint!("\u{1F3EE} "); eprintln!($($tt)*);};
    (@diya_lamp $($tt:tt)*) => { eprint!("\u{1FA94} "); eprintln!($($tt)*);};
    (@notebook_with_decorative_cover $($tt:tt)*) => { eprint!("\u{1F4D4} "); eprintln!($($tt)*);};
    (@closed_book $($tt:tt)*) => { eprint!("\u{1F4D5} "); eprintln!($($tt)*);};
    (@open_book $($tt:tt)*) => { eprint!("\u{1F4D6} "); eprintln!($($tt)*);};
    (@green_book $($tt:tt)*) => { eprint!("\u{1F4D7} "); eprintln!($($tt)*);};
    (@blue_book $($tt:tt)*) => { eprint!("\u{1F4D8} "); eprintln!($($tt)*);};
    (@orange_book $($tt:tt)*) => { eprint!("\u{1F4D9} "); eprintln!($($tt)*);};
    (@books $($tt:tt)*) => { eprint!("\u{1F4DA} "); eprintln!($($tt)*);};
    (@notebook $($tt:tt)*) => { eprint!("\u{1F4D3} "); eprintln!($($tt)*);};
    (@ledger $($tt:tt)*) => { eprint!("\u{1F4D2} "); eprintln!($($tt)*);};
    (@page_with_curl $($tt:tt)*) => { eprint!("\u{1F4C3} "); eprintln!($($tt)*);};
    (@scroll $($tt:tt)*) => { eprint!("\u{1F4DC} "); eprintln!($($tt)*);};
    (@page_facing_up $($tt:tt)*) => { eprint!("\u{1F4C4} "); eprintln!($($tt)*);};
    (@newspaper $($tt:tt)*) => { eprint!("\u{1F4F0} "); eprintln!($($tt)*);};
    (@rolled_up_newspaper $($tt:tt)*) => { eprint!("\u{1F5DE} "); eprintln!($($tt)*);};
    (@bookmark_tabs $($tt:tt)*) => { eprint!("\u{1F4D1} "); eprintln!($($tt)*);};
    (@bookmark $($tt:tt)*) => { eprint!("\u{1F516} "); eprintln!($($tt)*);};
    (@label $($tt:tt)*) => { eprint!("\u{1F3F7} "); eprintln!($($tt)*);};
    (@money_bag $($tt:tt)*) => { eprint!("\u{1F4B0} "); eprintln!($($tt)*);};
    (@coin $($tt:tt)*) => { eprint!("\u{1FA99} "); eprintln!($($tt)*);};
    (@yen_banknote $($tt:tt)*) => { eprint!("\u{1F4B4} "); eprintln!($($tt)*);};
    (@dollar_banknote $($tt:tt)*) => { eprint!("\u{1F4B5} "); eprintln!($($tt)*);};
    (@euro_banknote $($tt:tt)*) => { eprint!("\u{1F4B6} "); eprintln!($($tt)*);};
    (@pound_banknote $($tt:tt)*) => { eprint!("\u{1F4B7} "); eprintln!($($tt)*);};
    (@money_with_wings $($tt:tt)*) => { eprint!("\u{1F4B8} "); eprintln!($($tt)*);};
    (@credit_card $($tt:tt)*) => { eprint!("\u{1F4B3} "); eprintln!($($tt)*);};
    (@receipt $($tt:tt)*) => { eprint!("\u{1F9FE} "); eprintln!($($tt)*);};
    (@chart_increasing_with_yen $($tt:tt)*) => { eprint!("\u{1F4B9} "); eprintln!($($tt)*);};
    (@envelope $($tt:tt)*) => { eprint!("\u{2709} "); eprintln!($($tt)*);};
    (@e_mail $($tt:tt)*) => { eprint!("\u{1F4E7} "); eprintln!($($tt)*);};
    (@incoming_envelope $($tt:tt)*) => { eprint!("\u{1F4E8} "); eprintln!($($tt)*);};
    (@envelope_with_arrow $($tt:tt)*) => { eprint!("\u{1F4E9} "); eprintln!($($tt)*);};
    (@outbox_tray $($tt:tt)*) => { eprint!("\u{1F4E4} "); eprintln!($($tt)*);};
    (@inbox_tray $($tt:tt)*) => { eprint!("\u{1F4E5} "); eprintln!($($tt)*);};
    (@package $($tt:tt)*) => { eprint!("\u{1F4E6} "); eprintln!($($tt)*);};
    (@closed_mailbox_with_raised_flag $($tt:tt)*) => { eprint!("\u{1F4EB} "); eprintln!($($tt)*);};
    (@closed_mailbox_with_lowered_flag $($tt:tt)*) => { eprint!("\u{1F4EA} "); eprintln!($($tt)*);};
    (@open_mailbox_with_raised_flag $($tt:tt)*) => { eprint!("\u{1F4EC} "); eprintln!($($tt)*);};
    (@open_mailbox_with_lowered_flag $($tt:tt)*) => { eprint!("\u{1F4ED} "); eprintln!($($tt)*);};
    (@postbox $($tt:tt)*) => { eprint!("\u{1F4EE} "); eprintln!($($tt)*);};
    (@ballot_box_with_ballot $($tt:tt)*) => { eprint!("\u{1F5F3} "); eprintln!($($tt)*);};
    (@pencil $($tt:tt)*) => { eprint!("\u{270F} "); eprintln!($($tt)*);};
    (@black_nib $($tt:tt)*) => { eprint!("\u{2712} "); eprintln!($($tt)*);};
    (@fountain_pen $($tt:tt)*) => { eprint!("\u{1F58B} "); eprintln!($($tt)*);};
    (@pen $($tt:tt)*) => { eprint!("\u{1F58A} "); eprintln!($($tt)*);};
    (@paintbrush $($tt:tt)*) => { eprint!("\u{1F58C} "); eprintln!($($tt)*);};
    (@crayon $($tt:tt)*) => { eprint!("\u{1F58D} "); eprintln!($($tt)*);};
    (@memo $($tt:tt)*) => { eprint!("\u{1F4DD} "); eprintln!($($tt)*);};
    (@briefcase $($tt:tt)*) => { eprint!("\u{1F4BC} "); eprintln!($($tt)*);};
    (@file_folder $($tt:tt)*) => { eprint!("\u{1F4C1} "); eprintln!($($tt)*);};
    (@open_file_folder $($tt:tt)*) => { eprint!("\u{1F4C2} "); eprintln!($($tt)*);};
    (@card_index_dividers $($tt:tt)*) => { eprint!("\u{1F5C2} "); eprintln!($($tt)*);};
    (@calendar $($tt:tt)*) => { eprint!("\u{1F4C5} "); eprintln!($($tt)*);};
    (@tear_off_calendar $($tt:tt)*) => { eprint!("\u{1F4C6} "); eprintln!($($tt)*);};
    (@spiral_notepad $($tt:tt)*) => { eprint!("\u{1F5D2} "); eprintln!($($tt)*);};
    (@spiral_calendar $($tt:tt)*) => { eprint!("\u{1F5D3} "); eprintln!($($tt)*);};
    (@card_index $($tt:tt)*) => { eprint!("\u{1F4C7} "); eprintln!($($tt)*);};
    (@chart_increasing $($tt:tt)*) => { eprint!("\u{1F4C8} "); eprintln!($($tt)*);};
    (@chart_decreasing $($tt:tt)*) => { eprint!("\u{1F4C9} "); eprintln!($($tt)*);};
    (@bar_chart $($tt:tt)*) => { eprint!("\u{1F4CA} "); eprintln!($($tt)*);};
    (@clipboard $($tt:tt)*) => { eprint!("\u{1F4CB} "); eprintln!($($tt)*);};
    (@pushpin $($tt:tt)*) => { eprint!("\u{1F4CC} "); eprintln!($($tt)*);};
    (@round_pushpin $($tt:tt)*) => { eprint!("\u{1F4CD} "); eprintln!($($tt)*);};
    (@paperclip $($tt:tt)*) => { eprint!("\u{1F4CE} "); eprintln!($($tt)*);};
    (@linked_paperclips $($tt:tt)*) => { eprint!("\u{1F587} "); eprintln!($($tt)*);};
    (@straight_ruler $($tt:tt)*) => { eprint!("\u{1F4CF} "); eprintln!($($tt)*);};
    (@triangular_ruler $($tt:tt)*) => { eprint!("\u{1F4D0} "); eprintln!($($tt)*);};
    (@scissors $($tt:tt)*) => { eprint!("\u{2702} "); eprintln!($($tt)*);};
    (@card_file_box $($tt:tt)*) => { eprint!("\u{1F5C3} "); eprintln!($($tt)*);};
    (@file_cabinet $($tt:tt)*) => { eprint!("\u{1F5C4} "); eprintln!($($tt)*);};
    (@wastebasket $($tt:tt)*) => { eprint!("\u{1F5D1} "); eprintln!($($tt)*);};
    (@locked $($tt:tt)*) => { eprint!("\u{1F512} "); eprintln!($($tt)*);};
    (@unlocked $($tt:tt)*) => { eprint!("\u{1F513} "); eprintln!($($tt)*);};
    (@locked_with_pen $($tt:tt)*) => { eprint!("\u{1F50F} "); eprintln!($($tt)*);};
    (@locked_with_key $($tt:tt)*) => { eprint!("\u{1F510} "); eprintln!($($tt)*);};
    (@key $($tt:tt)*) => { eprint!("\u{1F511} "); eprintln!($($tt)*);};
    (@old_key $($tt:tt)*) => { eprint!("\u{1F5DD} "); eprintln!($($tt)*);};
    (@hammer $($tt:tt)*) => { eprint!("\u{1F528} "); eprintln!($($tt)*);};
    (@axe $($tt:tt)*) => { eprint!("\u{1FA93} "); eprintln!($($tt)*);};
    (@pick $($tt:tt)*) => { eprint!("\u{26CF} "); eprintln!($($tt)*);};
    (@hammer_and_pick $($tt:tt)*) => { eprint!("\u{2692} "); eprintln!($($tt)*);};
    (@hammer_and_wrench $($tt:tt)*) => { eprint!("\u{1F6E0} "); eprintln!($($tt)*);};
    (@dagger $($tt:tt)*) => { eprint!("\u{1F5E1} "); eprintln!($($tt)*);};
    (@crossed_swords $($tt:tt)*) => { eprint!("\u{2694} "); eprintln!($($tt)*);};
    (@water_pistol $($tt:tt)*) => { eprint!("\u{1F52B} "); eprintln!($($tt)*);};
    (@boomerang $($tt:tt)*) => { eprint!("\u{1FA83} "); eprintln!($($tt)*);};
    (@bow_and_arrow $($tt:tt)*) => { eprint!("\u{1F3F9} "); eprintln!($($tt)*);};
    (@shield $($tt:tt)*) => { eprint!("\u{1F6E1} "); eprintln!($($tt)*);};
    (@carpentry_saw $($tt:tt)*) => { eprint!("\u{1FA9A} "); eprintln!($($tt)*);};
    (@wrench $($tt:tt)*) => { eprint!("\u{1F527} "); eprintln!($($tt)*);};
    (@screwdriver $($tt:tt)*) => { eprint!("\u{1FA9B} "); eprintln!($($tt)*);};
    (@nut_and_bolt $($tt:tt)*) => { eprint!("\u{1F529} "); eprintln!($($tt)*);};
    (@gear $($tt:tt)*) => { eprint!("\u{2699} "); eprintln!($($tt)*);};
    (@clamp $($tt:tt)*) => { eprint!("\u{1F5DC} "); eprintln!($($tt)*);};
    (@balance_scale $($tt:tt)*) => { eprint!("\u{2696} "); eprintln!($($tt)*);};
    (@white_cane $($tt:tt)*) => { eprint!("\u{1F9AF} "); eprintln!($($tt)*);};
    (@link $($tt:tt)*) => { eprint!("\u{1F517} "); eprintln!($($tt)*);};
    (@chains $($tt:tt)*) => { eprint!("\u{26D3} "); eprintln!($($tt)*);};
    (@hook $($tt:tt)*) => { eprint!("\u{1FA9D} "); eprintln!($($tt)*);};
    (@toolbox $($tt:tt)*) => { eprint!("\u{1F9F0} "); eprintln!($($tt)*);};
    (@magnet $($tt:tt)*) => { eprint!("\u{1F9F2} "); eprintln!($($tt)*);};
    (@ladder $($tt:tt)*) => { eprint!("\u{1FA9C} "); eprintln!($($tt)*);};
    (@alembic $($tt:tt)*) => { eprint!("\u{2697} "); eprintln!($($tt)*);};
    (@test_tube $($tt:tt)*) => { eprint!("\u{1F9EA} "); eprintln!($($tt)*);};
    (@petri_dish $($tt:tt)*) => { eprint!("\u{1F9EB} "); eprintln!($($tt)*);};
    (@dna $($tt:tt)*) => { eprint!("\u{1F9EC} "); eprintln!($($tt)*);};
    (@microscope $($tt:tt)*) => { eprint!("\u{1F52C} "); eprintln!($($tt)*);};
    (@telescope $($tt:tt)*) => { eprint!("\u{1F52D} "); eprintln!($($tt)*);};
    (@satellite_antenna $($tt:tt)*) => { eprint!("\u{1F4E1} "); eprintln!($($tt)*);};
    (@syringe $($tt:tt)*) => { eprint!("\u{1F489} "); eprintln!($($tt)*);};
    (@drop_of_blood $($tt:tt)*) => { eprint!("\u{1FA78} "); eprintln!($($tt)*);};
    (@pill $($tt:tt)*) => { eprint!("\u{1F48A} "); eprintln!($($tt)*);};
    (@adhesive_bandage $($tt:tt)*) => { eprint!("\u{1FA79} "); eprintln!($($tt)*);};
    (@crutch_ $($tt:tt)*) => { eprint!("\u{1FA7C} "); eprintln!($($tt)*);};
    (@stethoscope $($tt:tt)*) => { eprint!("\u{1FA7A} "); eprintln!($($tt)*);};
    (@xray_ $($tt:tt)*) => { eprint!("\u{1FA7B} "); eprintln!($($tt)*);};
    (@door $($tt:tt)*) => { eprint!("\u{1F6AA} "); eprintln!($($tt)*);};
    (@elevator $($tt:tt)*) => { eprint!("\u{1F6D7} "); eprintln!($($tt)*);};
    (@mirror $($tt:tt)*) => { eprint!("\u{1FA9E} "); eprintln!($($tt)*);};
    (@window $($tt:tt)*) => { eprint!("\u{1FA9F} "); eprintln!($($tt)*);};
    (@bed $($tt:tt)*) => { eprint!("\u{1F6CF} "); eprintln!($($tt)*);};
    (@couch_and_lamp $($tt:tt)*) => { eprint!("\u{1F6CB} "); eprintln!($($tt)*);};
    (@chair $($tt:tt)*) => { eprint!("\u{1FA91} "); eprintln!($($tt)*);};
    (@toilet $($tt:tt)*) => { eprint!("\u{1F6BD} "); eprintln!($($tt)*);};
    (@plunger $($tt:tt)*) => { eprint!("\u{1FAA0} "); eprintln!($($tt)*);};
    (@shower $($tt:tt)*) => { eprint!("\u{1F6BF} "); eprintln!($($tt)*);};
    (@bathtub $($tt:tt)*) => { eprint!("\u{1F6C1} "); eprintln!($($tt)*);};
    (@mouse_trap $($tt:tt)*) => { eprint!("\u{1FAA4} "); eprintln!($($tt)*);};
    (@razor $($tt:tt)*) => { eprint!("\u{1FA92} "); eprintln!($($tt)*);};
    (@lotion_bottle $($tt:tt)*) => { eprint!("\u{1F9F4} "); eprintln!($($tt)*);};
    (@safety_pin $($tt:tt)*) => { eprint!("\u{1F9F7} "); eprintln!($($tt)*);};
    (@broom $($tt:tt)*) => { eprint!("\u{1F9F9} "); eprintln!($($tt)*);};
    (@basket $($tt:tt)*) => { eprint!("\u{1F9FA} "); eprintln!($($tt)*);};
    (@roll_of_paper $($tt:tt)*) => { eprint!("\u{1F9FB} "); eprintln!($($tt)*);};
    (@bucket $($tt:tt)*) => { eprint!("\u{1FAA3} "); eprintln!($($tt)*);};
    (@soap $($tt:tt)*) => { eprint!("\u{1F9FC} "); eprintln!($($tt)*);};
    (@bubbles_ $($tt:tt)*) => { eprint!("\u{1FAE7} "); eprintln!($($tt)*);};
    (@toothbrush $($tt:tt)*) => { eprint!("\u{1FAA5} "); eprintln!($($tt)*);};
    (@sponge $($tt:tt)*) => { eprint!("\u{1F9FD} "); eprintln!($($tt)*);};
    (@fire_extinguisher $($tt:tt)*) => { eprint!("\u{1F9EF} "); eprintln!($($tt)*);};
    (@shopping_cart $($tt:tt)*) => { eprint!("\u{1F6D2} "); eprintln!($($tt)*);};
    (@cigarette $($tt:tt)*) => { eprint!("\u{1F6AC} "); eprintln!($($tt)*);};
    (@coffin $($tt:tt)*) => { eprint!("\u{26B0} "); eprintln!($($tt)*);};
    (@headstone $($tt:tt)*) => { eprint!("\u{1FAA6} "); eprintln!($($tt)*);};
    (@funeral_urn $($tt:tt)*) => { eprint!("\u{26B1} "); eprintln!($($tt)*);};
    (@moai $($tt:tt)*) => { eprint!("\u{1F5FF} "); eprintln!($($tt)*);};
    (@placard $($tt:tt)*) => { eprint!("\u{1FAA7} "); eprintln!($($tt)*);};
    (@identification_card_ $($tt:tt)*) => { eprint!("\u{1FAAA} "); eprintln!($($tt)*);};
    (@atm_sign $($tt:tt)*) => { eprint!("\u{1F3E7} "); eprintln!($($tt)*);};
    (@litter_in_bin_sign $($tt:tt)*) => { eprint!("\u{1F6AE} "); eprintln!($($tt)*);};
    (@potable_water $($tt:tt)*) => { eprint!("\u{1F6B0} "); eprintln!($($tt)*);};
    (@wheelchair_symbol $($tt:tt)*) => { eprint!("\u{267F} "); eprintln!($($tt)*);};
    (@mens_room $($tt:tt)*) => { eprint!("\u{1F6B9} "); eprintln!($($tt)*);};
    (@womens_room $($tt:tt)*) => { eprint!("\u{1F6BA} "); eprintln!($($tt)*);};
    (@restroom $($tt:tt)*) => { eprint!("\u{1F6BB} "); eprintln!($($tt)*);};
    (@baby_symbol $($tt:tt)*) => { eprint!("\u{1F6BC} "); eprintln!($($tt)*);};
    (@water_closet $($tt:tt)*) => { eprint!("\u{1F6BE} "); eprintln!($($tt)*);};
    (@passport_control $($tt:tt)*) => { eprint!("\u{1F6C2} "); eprintln!($($tt)*);};
    (@customs $($tt:tt)*) => { eprint!("\u{1F6C3} "); eprintln!($($tt)*);};
    (@baggage_claim $($tt:tt)*) => { eprint!("\u{1F6C4} "); eprintln!($($tt)*);};
    (@left_luggage $($tt:tt)*) => { eprint!("\u{1F6C5} "); eprintln!($($tt)*);};
    (@warning $($tt:tt)*) => { eprint!("\u{26A0} "); eprintln!($($tt)*);};
    (@children_crossing $($tt:tt)*) => { eprint!("\u{1F6B8} "); eprintln!($($tt)*);};
    (@no_entry $($tt:tt)*) => { eprint!("\u{26D4} "); eprintln!($($tt)*);};
    (@prohibited $($tt:tt)*) => { eprint!("\u{1F6AB} "); eprintln!($($tt)*);};
    (@no_bicycles $($tt:tt)*) => { eprint!("\u{1F6B3} "); eprintln!($($tt)*);};
    (@no_smoking $($tt:tt)*) => { eprint!("\u{1F6AD} "); eprintln!($($tt)*);};
    (@no_littering $($tt:tt)*) => { eprint!("\u{1F6AF} "); eprintln!($($tt)*);};
    (@nonpotable_water $($tt:tt)*) => { eprint!("\u{1F6B1} "); eprintln!($($tt)*);};
    (@no_pedestrians $($tt:tt)*) => { eprint!("\u{1F6B7} "); eprintln!($($tt)*);};
    (@no_mobile_phones $($tt:tt)*) => { eprint!("\u{1F4F5} "); eprintln!($($tt)*);};
    (@no_one_under_eighteen $($tt:tt)*) => { eprint!("\u{1F51E} "); eprintln!($($tt)*);};
    (@radioactive $($tt:tt)*) => { eprint!("\u{2622} "); eprintln!($($tt)*);};
    (@biohazard $($tt:tt)*) => { eprint!("\u{2623} "); eprintln!($($tt)*);};
    (@up_arrow $($tt:tt)*) => { eprint!("\u{2B06} "); eprintln!($($tt)*);};
    (@up_right_arrow $($tt:tt)*) => { eprint!("\u{2197} "); eprintln!($($tt)*);};
    (@right_arrow $($tt:tt)*) => { eprint!("\u{27A1} "); eprintln!($($tt)*);};
    (@down_right_arrow $($tt:tt)*) => { eprint!("\u{2198} "); eprintln!($($tt)*);};
    (@down_arrow $($tt:tt)*) => { eprint!("\u{2B07} "); eprintln!($($tt)*);};
    (@down_left_arrow $($tt:tt)*) => { eprint!("\u{2199} "); eprintln!($($tt)*);};
    (@left_arrow $($tt:tt)*) => { eprint!("\u{2B05} "); eprintln!($($tt)*);};
    (@up_left_arrow $($tt:tt)*) => { eprint!("\u{2196} "); eprintln!($($tt)*);};
    (@up_down_arrow $($tt:tt)*) => { eprint!("\u{2195} "); eprintln!($($tt)*);};
    (@left_right_arrow $($tt:tt)*) => { eprint!("\u{2194} "); eprintln!($($tt)*);};
    (@right_arrow_curving_left $($tt:tt)*) => { eprint!("\u{21A9} "); eprintln!($($tt)*);};
    (@left_arrow_curving_right $($tt:tt)*) => { eprint!("\u{21AA} "); eprintln!($($tt)*);};
    (@right_arrow_curving_up $($tt:tt)*) => { eprint!("\u{2934} "); eprintln!($($tt)*);};
    (@right_arrow_curving_down $($tt:tt)*) => { eprint!("\u{2935} "); eprintln!($($tt)*);};
    (@clockwise_vertical_arrows $($tt:tt)*) => { eprint!("\u{1F503} "); eprintln!($($tt)*);};
    (@counterclockwise_arrows_button $($tt:tt)*) => { eprint!("\u{1F504} "); eprintln!($($tt)*);};
    (@back_arrow $($tt:tt)*) => { eprint!("\u{1F519} "); eprintln!($($tt)*);};
    (@end_arrow $($tt:tt)*) => { eprint!("\u{1F51A} "); eprintln!($($tt)*);};
    (@on_arrow $($tt:tt)*) => { eprint!("\u{1F51B} "); eprintln!($($tt)*);};
    (@soon_arrow $($tt:tt)*) => { eprint!("\u{1F51C} "); eprintln!($($tt)*);};
    (@top_arrow $($tt:tt)*) => { eprint!("\u{1F51D} "); eprintln!($($tt)*);};
    (@place_of_worship $($tt:tt)*) => { eprint!("\u{1F6D0} "); eprintln!($($tt)*);};
    (@atom_symbol $($tt:tt)*) => { eprint!("\u{269B} "); eprintln!($($tt)*);};
    (@om $($tt:tt)*) => { eprint!("\u{1F549} "); eprintln!($($tt)*);};
    (@star_of_david $($tt:tt)*) => { eprint!("\u{2721} "); eprintln!($($tt)*);};
    (@wheel_of_dharma $($tt:tt)*) => { eprint!("\u{2638} "); eprintln!($($tt)*);};
    (@yin_yang $($tt:tt)*) => { eprint!("\u{262F} "); eprintln!($($tt)*);};
    (@latin_cross $($tt:tt)*) => { eprint!("\u{271D} "); eprintln!($($tt)*);};
    (@orthodox_cross $($tt:tt)*) => { eprint!("\u{2626} "); eprintln!($($tt)*);};
    (@star_and_crescent $($tt:tt)*) => { eprint!("\u{262A} "); eprintln!($($tt)*);};
    (@peace_symbol $($tt:tt)*) => { eprint!("\u{262E} "); eprintln!($($tt)*);};
    (@menorah $($tt:tt)*) => { eprint!("\u{1F54E} "); eprintln!($($tt)*);};
    (@dotted_six_pointed_star $($tt:tt)*) => { eprint!("\u{1F52F} "); eprintln!($($tt)*);};
    (@aries $($tt:tt)*) => { eprint!("\u{2648} "); eprintln!($($tt)*);};
    (@taurus $($tt:tt)*) => { eprint!("\u{2649} "); eprintln!($($tt)*);};
    (@gemini $($tt:tt)*) => { eprint!("\u{264A} "); eprintln!($($tt)*);};
    (@cancer $($tt:tt)*) => { eprint!("\u{264B} "); eprintln!($($tt)*);};
    (@leo $($tt:tt)*) => { eprint!("\u{264C} "); eprintln!($($tt)*);};
    (@virgo $($tt:tt)*) => { eprint!("\u{264D} "); eprintln!($($tt)*);};
    (@libra $($tt:tt)*) => { eprint!("\u{264E} "); eprintln!($($tt)*);};
    (@scorpio $($tt:tt)*) => { eprint!("\u{264F} "); eprintln!($($tt)*);};
    (@sagittarius $($tt:tt)*) => { eprint!("\u{2650} "); eprintln!($($tt)*);};
    (@capricorn $($tt:tt)*) => { eprint!("\u{2651} "); eprintln!($($tt)*);};
    (@aquarius $($tt:tt)*) => { eprint!("\u{2652} "); eprintln!($($tt)*);};
    (@pisces $($tt:tt)*) => { eprint!("\u{2653} "); eprintln!($($tt)*);};
    (@ophiuchus $($tt:tt)*) => { eprint!("\u{26CE} "); eprintln!($($tt)*);};
    (@shuffle_tracks_button $($tt:tt)*) => { eprint!("\u{1F500} "); eprintln!($($tt)*);};
    (@repeat_button $($tt:tt)*) => { eprint!("\u{1F501} "); eprintln!($($tt)*);};
    (@repeat_single_button $($tt:tt)*) => { eprint!("\u{1F502} "); eprintln!($($tt)*);};
    (@play_button $($tt:tt)*) => { eprint!("\u{25B6} "); eprintln!($($tt)*);};
    (@fast_forward_button $($tt:tt)*) => { eprint!("\u{23E9} "); eprintln!($($tt)*);};
    (@next_track_button $($tt:tt)*) => { eprint!("\u{23ED} "); eprintln!($($tt)*);};
    (@play_or_pause_button $($tt:tt)*) => { eprint!("\u{23EF} "); eprintln!($($tt)*);};
    (@reverse_button $($tt:tt)*) => { eprint!("\u{25C0} "); eprintln!($($tt)*);};
    (@fast_reverse_button $($tt:tt)*) => { eprint!("\u{23EA} "); eprintln!($($tt)*);};
    (@last_track_button $($tt:tt)*) => { eprint!("\u{23EE} "); eprintln!($($tt)*);};
    (@upwards_button $($tt:tt)*) => { eprint!("\u{1F53C} "); eprintln!($($tt)*);};
    (@fast_up_button $($tt:tt)*) => { eprint!("\u{23EB} "); eprintln!($($tt)*);};
    (@downwards_button $($tt:tt)*) => { eprint!("\u{1F53D} "); eprintln!($($tt)*);};
    (@fast_down_button $($tt:tt)*) => { eprint!("\u{23EC} "); eprintln!($($tt)*);};
    (@pause_button $($tt:tt)*) => { eprint!("\u{23F8} "); eprintln!($($tt)*);};
    (@stop_button $($tt:tt)*) => { eprint!("\u{23F9} "); eprintln!($($tt)*);};
    (@record_button $($tt:tt)*) => { eprint!("\u{23FA} "); eprintln!($($tt)*);};
    (@eject_button $($tt:tt)*) => { eprint!("\u{23CF} "); eprintln!($($tt)*);};
    (@cinema $($tt:tt)*) => { eprint!("\u{1F3A6} "); eprintln!($($tt)*);};
    (@dim_button $($tt:tt)*) => { eprint!("\u{1F505} "); eprintln!($($tt)*);};
    (@bright_button $($tt:tt)*) => { eprint!("\u{1F506} "); eprintln!($($tt)*);};
    (@antenna_bars $($tt:tt)*) => { eprint!("\u{1F4F6} "); eprintln!($($tt)*);};
    (@vibration_mode $($tt:tt)*) => { eprint!("\u{1F4F3} "); eprintln!($($tt)*);};
    (@mobile_phone_off $($tt:tt)*) => { eprint!("\u{1F4F4} "); eprintln!($($tt)*);};
    (@female_sign $($tt:tt)*) => { eprint!("\u{2640} "); eprintln!($($tt)*);};
    (@male_sign $($tt:tt)*) => { eprint!("\u{2642} "); eprintln!($($tt)*);};
    (@transgender_symbol $($tt:tt)*) => { eprint!("\u{26A7} "); eprintln!($($tt)*);};
    (@multiply $($tt:tt)*) => { eprint!("\u{2716} "); eprintln!($($tt)*);};
    (@plus $($tt:tt)*) => { eprint!("\u{2795} "); eprintln!($($tt)*);};
    (@minus $($tt:tt)*) => { eprint!("\u{2796} "); eprintln!($($tt)*);};
    (@divide $($tt:tt)*) => { eprint!("\u{2797} "); eprintln!($($tt)*);};
    (@heavy_equals_sign_ $($tt:tt)*) => { eprint!("\u{1F7F0} "); eprintln!($($tt)*);};
    (@infinity $($tt:tt)*) => { eprint!("\u{267E} "); eprintln!($($tt)*);};
    (@double_exclamation_mark $($tt:tt)*) => { eprint!("\u{203C} "); eprintln!($($tt)*);};
    (@exclamation_question_mark $($tt:tt)*) => { eprint!("\u{2049} "); eprintln!($($tt)*);};
    (@red_question_mark $($tt:tt)*) => { eprint!("\u{2753} "); eprintln!($($tt)*);};
    (@white_question_mark $($tt:tt)*) => { eprint!("\u{2754} "); eprintln!($($tt)*);};
    (@white_exclamation_mark $($tt:tt)*) => { eprint!("\u{2755} "); eprintln!($($tt)*);};
    (@red_exclamation_mark $($tt:tt)*) => { eprint!("\u{2757} "); eprintln!($($tt)*);};
    (@wavy_dash $($tt:tt)*) => { eprint!("\u{3030} "); eprintln!($($tt)*);};
    (@currency_exchange $($tt:tt)*) => { eprint!("\u{1F4B1} "); eprintln!($($tt)*);};
    (@heavy_dollar_sign $($tt:tt)*) => { eprint!("\u{1F4B2} "); eprintln!($($tt)*);};
    (@medical_symbol $($tt:tt)*) => { eprint!("\u{2695} "); eprintln!($($tt)*);};
    (@recycling_symbol $($tt:tt)*) => { eprint!("\u{267B} "); eprintln!($($tt)*);};
    (@fleur_de_lis $($tt:tt)*) => { eprint!("\u{269C} "); eprintln!($($tt)*);};
    (@trident_emblem $($tt:tt)*) => { eprint!("\u{1F531} "); eprintln!($($tt)*);};
    (@name_badge $($tt:tt)*) => { eprint!("\u{1F4DB} "); eprintln!($($tt)*);};
    (@hollow_red_circle $($tt:tt)*) => { eprint!("\u{2B55} "); eprintln!($($tt)*);};
    (@check_mark_button $($tt:tt)*) => { eprint!("\u{2705} "); eprintln!($($tt)*);};
    (@check_box_with_check $($tt:tt)*) => { eprint!("\u{2611} "); eprintln!($($tt)*);};
    (@check_mark $($tt:tt)*) => { eprint!("\u{2714} "); eprintln!($($tt)*);};
    (@cross_mark $($tt:tt)*) => { eprint!("\u{274C} "); eprintln!($($tt)*);};
    (@cross_mark_button $($tt:tt)*) => { eprint!("\u{274E} "); eprintln!($($tt)*);};
    (@curly_loop $($tt:tt)*) => { eprint!("\u{27B0} "); eprintln!($($tt)*);};
    (@double_curly_loop $($tt:tt)*) => { eprint!("\u{27BF} "); eprintln!($($tt)*);};
    (@part_alternation_mark $($tt:tt)*) => { eprint!("\u{303D} "); eprintln!($($tt)*);};
    (@eight_spoked_asterisk $($tt:tt)*) => { eprint!("\u{2733} "); eprintln!($($tt)*);};
    (@eight_pointed_star $($tt:tt)*) => { eprint!("\u{2734} "); eprintln!($($tt)*);};
    (@sparkle $($tt:tt)*) => { eprint!("\u{2747} "); eprintln!($($tt)*);};
    (@copyright $($tt:tt)*) => { eprint!("\u{00A9} "); eprintln!($($tt)*);};
    (@registered $($tt:tt)*) => { eprint!("\u{00AE} "); eprintln!($($tt)*);};
    (@trade_mark $($tt:tt)*) => { eprint!("\u{2122} "); eprintln!($($tt)*);};
    (@keycap $($tt:tt)*) => { eprint!("\u{0023} "); eprintln!($($tt)*);};
    (@keycap_0 $($tt:tt)*) => { eprint!("\u{0030} "); eprintln!($($tt)*);};
    (@keycap_1 $($tt:tt)*) => { eprint!("\u{0031} "); eprintln!($($tt)*);};
    (@keycap_2 $($tt:tt)*) => { eprint!("\u{0032} "); eprintln!($($tt)*);};
    (@keycap_3 $($tt:tt)*) => { eprint!("\u{0033} "); eprintln!($($tt)*);};
    (@keycap_4 $($tt:tt)*) => { eprint!("\u{0034} "); eprintln!($($tt)*);};
    (@keycap_5 $($tt:tt)*) => { eprint!("\u{0035} "); eprintln!($($tt)*);};
    (@keycap_6 $($tt:tt)*) => { eprint!("\u{0036} "); eprintln!($($tt)*);};
    (@keycap_7 $($tt:tt)*) => { eprint!("\u{0037} "); eprintln!($($tt)*);};
    (@keycap_8 $($tt:tt)*) => { eprint!("\u{0038} "); eprintln!($($tt)*);};
    (@keycap_9 $($tt:tt)*) => { eprint!("\u{0039} "); eprintln!($($tt)*);};
    (@keycap_10 $($tt:tt)*) => { eprint!("\u{1F51F} "); eprintln!($($tt)*);};
    (@input_latin_uppercase $($tt:tt)*) => { eprint!("\u{1F520} "); eprintln!($($tt)*);};
    (@input_latin_lowercase $($tt:tt)*) => { eprint!("\u{1F521} "); eprintln!($($tt)*);};
    (@input_numbers $($tt:tt)*) => { eprint!("\u{1F522} "); eprintln!($($tt)*);};
    (@input_symbols $($tt:tt)*) => { eprint!("\u{1F523} "); eprintln!($($tt)*);};
    (@input_latin_letters $($tt:tt)*) => { eprint!("\u{1F524} "); eprintln!($($tt)*);};
    (@cool_button $($tt:tt)*) => { eprint!("\u{1F192} "); eprintln!($($tt)*);};
    (@free_button $($tt:tt)*) => { eprint!("\u{1F193} "); eprintln!($($tt)*);};
    (@information $($tt:tt)*) => { eprint!("\u{2139} "); eprintln!($($tt)*);};
    (@id_button $($tt:tt)*) => { eprint!("\u{1F194} "); eprintln!($($tt)*);};
    (@circled_m $($tt:tt)*) => { eprint!("\u{24C2} "); eprintln!($($tt)*);};
    (@new_button $($tt:tt)*) => { eprint!("\u{1F195} "); eprintln!($($tt)*);};
    (@ng_button $($tt:tt)*) => { eprint!("\u{1F196} "); eprintln!($($tt)*);};
    (@o_button_blood_type $($tt:tt)*) => { eprint!("\u{1F17E} "); eprintln!($($tt)*);};
    (@ok_button $($tt:tt)*) => { eprint!("\u{1F197} "); eprintln!($($tt)*);};
    (@p_button $($tt:tt)*) => { eprint!("\u{1F17F} "); eprintln!($($tt)*);};
    (@sos_button $($tt:tt)*) => { eprint!("\u{1F198} "); eprintln!($($tt)*);};
    (@up_button $($tt:tt)*) => { eprint!("\u{1F199} "); eprintln!($($tt)*);};
    (@red_circle $($tt:tt)*) => { eprint!("\u{1F534} "); eprintln!($($tt)*);};
    (@orange_circle $($tt:tt)*) => { eprint!("\u{1F7E0} "); eprintln!($($tt)*);};
    (@yellow_circle $($tt:tt)*) => { eprint!("\u{1F7E1} "); eprintln!($($tt)*);};
    (@green_circle $($tt:tt)*) => { eprint!("\u{1F7E2} "); eprintln!($($tt)*);};
    (@blue_circle $($tt:tt)*) => { eprint!("\u{1F535} "); eprintln!($($tt)*);};
    (@purple_circle $($tt:tt)*) => { eprint!("\u{1F7E3} "); eprintln!($($tt)*);};
    (@brown_circle $($tt:tt)*) => { eprint!("\u{1F7E4} "); eprintln!($($tt)*);};
    (@black_circle $($tt:tt)*) => { eprint!("\u{26AB} "); eprintln!($($tt)*);};
    (@white_circle $($tt:tt)*) => { eprint!("\u{26AA} "); eprintln!($($tt)*);};
    (@red_square $($tt:tt)*) => { eprint!("\u{1F7E5} "); eprintln!($($tt)*);};
    (@orange_square $($tt:tt)*) => { eprint!("\u{1F7E7} "); eprintln!($($tt)*);};
    (@yellow_square $($tt:tt)*) => { eprint!("\u{1F7E8} "); eprintln!($($tt)*);};
    (@green_square $($tt:tt)*) => { eprint!("\u{1F7E9} "); eprintln!($($tt)*);};
    (@blue_square $($tt:tt)*) => { eprint!("\u{1F7E6} "); eprintln!($($tt)*);};
    (@purple_square $($tt:tt)*) => { eprint!("\u{1F7EA} "); eprintln!($($tt)*);};
    (@brown_square $($tt:tt)*) => { eprint!("\u{1F7EB} "); eprintln!($($tt)*);};
    (@black_large_square $($tt:tt)*) => { eprint!("\u{2B1B} "); eprintln!($($tt)*);};
    (@white_large_square $($tt:tt)*) => { eprint!("\u{2B1C} "); eprintln!($($tt)*);};
    (@black_medium_square $($tt:tt)*) => { eprint!("\u{25FC} "); eprintln!($($tt)*);};
    (@white_medium_square $($tt:tt)*) => { eprint!("\u{25FB} "); eprintln!($($tt)*);};
    (@black_medium_small_square $($tt:tt)*) => { eprint!("\u{25FE} "); eprintln!($($tt)*);};
    (@white_medium_small_square $($tt:tt)*) => { eprint!("\u{25FD} "); eprintln!($($tt)*);};
    (@black_small_square $($tt:tt)*) => { eprint!("\u{25AA} "); eprintln!($($tt)*);};
    (@white_small_square $($tt:tt)*) => { eprint!("\u{25AB} "); eprintln!($($tt)*);};
    (@large_orange_diamond $($tt:tt)*) => { eprint!("\u{1F536} "); eprintln!($($tt)*);};
    (@large_blue_diamond $($tt:tt)*) => { eprint!("\u{1F537} "); eprintln!($($tt)*);};
    (@small_orange_diamond $($tt:tt)*) => { eprint!("\u{1F538} "); eprintln!($($tt)*);};
    (@small_blue_diamond $($tt:tt)*) => { eprint!("\u{1F539} "); eprintln!($($tt)*);};
    (@red_triangle_pointed_up $($tt:tt)*) => { eprint!("\u{1F53A} "); eprintln!($($tt)*);};
    (@red_triangle_pointed_down $($tt:tt)*) => { eprint!("\u{1F53B} "); eprintln!($($tt)*);};
    (@diamond_with_a_dot $($tt:tt)*) => { eprint!("\u{1F4A0} "); eprintln!($($tt)*);};
    (@radio_button $($tt:tt)*) => { eprint!("\u{1F518} "); eprintln!($($tt)*);};
    (@white_square_button $($tt:tt)*) => { eprint!("\u{1F533} "); eprintln!($($tt)*);};
    (@black_square_button $($tt:tt)*) => { eprint!("\u{1F532} "); eprintln!($($tt)*);};
    (@chequered_flag $($tt:tt)*) => { eprint!("\u{1F3C1} "); eprintln!($($tt)*);};
    (@triangular_flag $($tt:tt)*) => { eprint!("\u{1F6A9} "); eprintln!($($tt)*);};
    (@crossed_flags $($tt:tt)*) => { eprint!("\u{1F38C} "); eprintln!($($tt)*);};
    (@black_flag $($tt:tt)*) => { eprint!("\u{1F3F4} "); eprintln!($($tt)*);};
    (@white_flag $($tt:tt)*) => { eprint!("\u{1F3F3} "); eprintln!($($tt)*);};
    (@rainbow_flag $($tt:tt)*) => { eprint!("\u{1F3F3} "); eprintln!($($tt)*);};
    (@transgender_flag $($tt:tt)*) => { eprint!("\u{1F3F3} "); eprintln!($($tt)*);};
    (@pirate_flag $($tt:tt)*) => { eprint!("\u{1F3F4} "); eprintln!($($tt)*);};
}
