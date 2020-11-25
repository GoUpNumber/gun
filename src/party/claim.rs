use super::Party;
use crate::bet_database::{BetDatabase, BetId, BetState};
use anyhow::anyhow;
use bdk::{
    bitcoin::Transaction,
    blockchain::{noop_progress, Blockchain},
    database::BatchDatabase,
    TxBuilder,
};
use olivia_secp256k1::fun::{marker::*, Scalar};

impl<B: Blockchain, D: BatchDatabase, BD: BetDatabase> Party<B, D, BD> {
    pub async fn claim(
        &self,
        bet_id: BetId,
        outcome_scalar: Scalar<Public, Zero>,
    ) -> anyhow::Result<Transaction> {
        let bet = self
            .bets_db
            .get_bet(bet_id)?
            .ok_or(anyhow!("Bet doesn't exist"))?;
        match bet {
            BetState::Proposed { .. } => {
                Err(anyhow!("You can't calim a bet that has only been proposed"))
            }
            BetState::Confirmed { bet, .. } => {
                let wallet = bet
                    .joint_output
                    .claim(self.new_blockchain(), outcome_scalar)
                    .await?;
                wallet.sync(noop_progress(), Some(1)).await?;
                if wallet
                    .list_transactions(false)?
                    .iter()
                    .find(|t| t.txid == bet.funding_txid)
                    .is_none()
                {
                    return Err(anyhow!(
                        "BDK wallet hasn't recognised our funding transaction output"
                    ));
                }

                let (psbt, _) = wallet.create_tx(
                    TxBuilder::new()
                        .set_single_recipient(self.wallet.get_new_address()?.script_pubkey())
                        .drain_wallet(),
                )?;
                let (psbt, is_final) = wallet.sign(psbt, None)?;
                if !is_final {
                    return Err(anyhow!("Failed to sign calim transaction"));
                }

                let tx = psbt.extract_tx();
                wallet.broadcast(tx.clone()).await?;
                Ok(tx)
            }
            _ => unimplemented!(),
        }
    }
}
