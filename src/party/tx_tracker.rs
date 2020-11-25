use bdk::{
    bitcoin, bitcoin::Network, blockchain::Blockchain, database::MemoryDatabase,
    descriptor::ExtendedDescriptor, TransactionDetails, Wallet,
};

pub struct TxTracker<B> {
    txid: bitcoin::Txid,
    inner: Wallet<B, MemoryDatabase>,
}

impl<B: Blockchain> TxTracker<B> {
    pub async fn new(
        txid: bitcoin::Txid,
        descriptor: ExtendedDescriptor,
        blockchain: B,
        network: Network,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            txid,
            inner: Wallet::new(
                descriptor,
                None,
                network,
                MemoryDatabase::default(),
                blockchain,
            )
            .await?,
        })
    }

    pub async fn confirmed(&self) -> anyhow::Result<Option<TransactionDetails>> {
        self.inner
            .sync(bdk::blockchain::noop_progress(), None)
            .await?;
        Ok(self
            .inner
            .list_transactions(true)?
            .iter()
            .find(|tx| tx.txid == self.txid)
            .and_then(|tx| tx.height.map(move |_| tx.clone())))
    }

    pub async fn wait_confirmed(&self) -> anyhow::Result<TransactionDetails> {
        let mut tx = None;
        while tx.is_none() {
            tx = self.confirmed().await?;
        }
        Ok(tx.unwrap())
    }
}
