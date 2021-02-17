mod claim;
mod joint_output;
mod offer;
mod proposal;
mod take_offer;
mod tx_tracker;

use bdk::{
    bitcoin::{OutPoint, TxOut},
    blockchain::EsploraBlockchain,
};
pub use joint_output::*;
pub use proposal::*;
pub use tx_tracker::*;

use crate::{
    bet_database::{BetDatabase, BetId},
    keychain::Keychain,
    reqwest,
};
use anyhow::anyhow;
use bdk::wallet::Wallet;
use core::borrow::Borrow;
pub use offer::*;
use olivia_core::{
    http::{EventResponse, RootResponse},
    OracleEvent, OracleId, OracleInfo,
};
use olivia_secp256k1::Secp256k1;

pub struct Party<B, D, BD> {
    wallet: Wallet<B, D>,
    keychain: Keychain,
    client: crate::reqwest::Client,
    bets_db: BD,
    #[allow(dead_code)]
    esplora_url: String,
}

impl<B, D, BD> Party<B, D, BD>
where
    BD: BetDatabase,
    B: bdk::blockchain::Blockchain,
    D: bdk::database::BatchDatabase,
{
    pub fn new(wallet: Wallet<B, D>, bets_db: BD, keychain: Keychain, esplora_url: String) -> Self {
        Self {
            wallet,
            keychain,
            bets_db,
            client: crate::reqwest::Client::new(),
            esplora_url,
        }
    }

    pub fn wallet(&self) -> &Wallet<B, D> {
        &self.wallet
    }

    pub fn bet_db(&self) -> &BD {
        &self.bets_db
    }

    pub async fn save_oracle_info(
        &self,
        oracle_id: OracleId,
    ) -> anyhow::Result<OracleInfo<Secp256k1>> {
        match self.bets_db.borrow().get_oracle_info(&oracle_id)? {
            Some(oracle_info) => Ok(oracle_info),
            None => {
                let root_resposne = self
                    .client
                    .get(&oracle_id)
                    .send()
                    .await?
                    .error_for_status()?
                    .json::<RootResponse<Secp256k1>>()
                    .await?;

                let oracle_info = OracleInfo {
                    id: oracle_id,
                    public_key: root_resposne.public_key,
                };

                self.bets_db.insert_oracle_info(oracle_info.clone())?;
                Ok(oracle_info)
            }
        }
    }

    pub async fn get_oracle_event_from_url(
        &self,
        url: reqwest::Url,
    ) -> anyhow::Result<OracleEvent<Secp256k1>> {
        let event_response = self
            .client
            .get(url.clone())
            .send()
            .await?
            .error_for_status()?
            .json::<EventResponse<Secp256k1>>()
            .await?;

        Ok(event_response
            .announcement
            .oracle_event
            .decode()
            .ok_or(anyhow!("unable to decode oracle event at {}", url))?)
    }

    pub fn bet_confirmed(&self, bet_id: BetId, height: u32) -> anyhow::Result<()> {
        self.bet_db().bet_confirmed(bet_id, height)
    }

    pub fn new_blockchain(&self) -> EsploraBlockchain {
        EsploraBlockchain::new(&self.esplora_url, None)
    }

    pub async fn get_txout(&self, outpoint: OutPoint) -> anyhow::Result<TxOut> {
        let tx = self
            .wallet
            .client()
            .get_tx(&outpoint.txid)
            .await?
            .ok_or(anyhow!("txid not found {}", outpoint.txid))?;

        let txout = tx
            .output
            .get(outpoint.vout as usize)
            .ok_or(anyhow!(
                "vout {} doesn't exist on txid {}",
                outpoint.vout,
                outpoint.txid
            ))?
            .clone();
        Ok(txout)
    }

    // pub async fn advance_state(&self) -> anyhow::Result<()> {
    //     for offer in self.bet_db().list_offers() {
    //         match  offer {
    //             OfferState::Offered {
    //                 local_offer
    //             } => {
    //                 let tx = TxTracker::new(local_offer.tx.txid(), local_offer.joint_output, EsploraBlockchain::new(self.esplora_url), self.wallet.network()).await?.confirmed().await?;
    //                 if let Some(tx) = tx {
    //                     self.offer_taken(local_offer.offer.id(), tx),
    //                 }
    //             }
    //             OfferState::Taken {
    //                 local_offer,
    //                 confirmed_tx,
    //             } => {
    //                 unimplemented!()
    //             }
    //         }
    //     }
    // }
}
