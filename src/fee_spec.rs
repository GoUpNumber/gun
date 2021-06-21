use std::str::FromStr;

use anyhow::anyhow;
use bdk::{
    bitcoin::Amount,
    blockchain::Blockchain,
    database::BatchDatabase,
    wallet::{coin_selection::CoinSelectionAlgorithm, tx_builder::TxBuilderContext},
    FeeRate, TxBuilder,
};

#[derive(Debug, Clone)]
///Hello
pub enum FeeSpec {
    Absolute(Amount),
    Rate(FeeRate),
    Height(u32),
}

impl Default for FeeSpec {
    fn default() -> Self {
        FeeSpec::Height(1)
    }
}

impl FeeSpec {
    pub fn apply_to_builder<
        B: Blockchain,
        D: BatchDatabase,
        Cs: CoinSelectionAlgorithm<D>,
        Ctx: TxBuilderContext,
    >(
        &self,
        blockchain: &B,
        builder: &mut TxBuilder<'_, B, D, Cs, Ctx>,
    ) -> anyhow::Result<()> {
        use FeeSpec::*;
        match self {
            Absolute(fee) => {
                builder.fee_absolute(fee.as_sat());
            }
            Rate(rate) => {
                builder.fee_rate(*rate);
            }
            Height(height) => {
                let feerate = blockchain.estimate_fee(*height as usize)?;
                builder.fee_rate(feerate);
            }
        }
        Ok(())
    }
}

impl FromStr for FeeSpec {
    type Err = anyhow::Error;

    fn from_str(string: &str) -> anyhow::Result<Self> {
        use crate::amount_ext::FromCliStr;

        if let Some(rate) = string.strip_prefix("spb:") {
            let rate = f32::from_str(rate)?;
            return Ok(FeeSpec::Rate(FeeRate::from_sat_per_vb(rate)));
        }

        if let Some(amount) = string.strip_prefix("abs:") {
            return Ok(FeeSpec::Absolute(Amount::from_cli_str(amount)?));
        }

        if let Some(in_blocks) = string.strip_prefix("in-blocks:") {
            let in_blocks = u32::from_str(in_blocks)?;
            return Ok(FeeSpec::Height(in_blocks));
        }

        return Err(anyhow!("{} is not a valid fee specification"));
    }
}

impl core::fmt::Display for FeeSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FeeSpec::Rate(rate) => write!(f, "spb:{}", rate.as_sat_vb()),
            FeeSpec::Absolute(abs) => write!(f, "abs:{}", abs),
            FeeSpec::Height(height) => write!(f, "in-blocks:{}", height),
        }
    }
}
