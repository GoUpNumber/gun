use anyhow::anyhow;
use bdk::{blockchain::Blockchain, database::BatchDatabase, Wallet};
use serde_json::json;

pub async fn fund_wallet(
    wallet: &Wallet<impl Blockchain, impl BatchDatabase>,
) -> anyhow::Result<()> {
    let new_address = wallet.get_new_address()?;
    dbg!(&new_address);
    let response = crate::reqwest::Client::new()
        .post("http://localhost:3000/faucet")
        .json(&json!({ "address": new_address }))
        .send()
        .await?;
    dbg!(response);
    Ok(())
}
