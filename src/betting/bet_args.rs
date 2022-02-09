use crate::{betting::*, database::GunDatabase, ValueChoice};
use anyhow::{anyhow, Context};
use bdk::{
    bitcoin::Amount,
    database::BatchDatabase,
    wallet::{coin_selection::CoinSelectionAlgorithm, tx_builder::TxBuilderContext},
    TxBuilder,
};

// TODO remove autism

pub struct BetArgs<'a, 'b> {
    pub value: ValueChoice,
    pub may_overlap: &'a [BetId],
    pub must_overlap: &'b [BetId],
    pub tags: Vec<String>,
}

impl Default for BetArgs<'_, '_> {
    fn default() -> Self {
        static EMPTY: [BetId; 0] = [];
        BetArgs {
            value: ValueChoice::Amount(Amount::ZERO),
            may_overlap: &EMPTY,
            must_overlap: &EMPTY,
            tags: vec![],
        }
    }
}

impl BetArgs<'_, '_> {
    pub fn apply_args<B, D: BatchDatabase, Cs: CoinSelectionAlgorithm<D>, Ctx: TxBuilderContext>(
        &self,
        gun_db: &GunDatabase,
        builder: &mut TxBuilder<B, D, Cs, Ctx>,
    ) -> anyhow::Result<()> {
        builder.unspendable(gun_db.currently_used_utxos(self.may_overlap)?);
        for bet_id in self.must_overlap {
            let bet = gun_db.get_entity::<BetState>(*bet_id)?.ok_or_else(|| {
                anyhow!("bet {} that we must overlap with does not exist", bet_id)
            })?;
            for input in bet.reserved_utxos() {
                builder.add_utxo(input).with_context(|| {
                    format!("adding utxo {} for 'must_overlap' with {}", input, bet_id)
                })?;
            }
        }

        Ok(())
    }
}
