use bdk::{
    bitcoin::{util::psbt::PartiallySignedTransaction as Psbt, Amount},
    FeeRate,
};

pub trait PsbtFeeRate {
    fn fee(&self) -> (Amount, FeeRate);
}

impl PsbtFeeRate for Psbt {
    fn fee(&self) -> (Amount, FeeRate) {
        let input_value: u64 = self
            .inputs
            .iter()
            .map(|x| x.witness_utxo.as_ref().map(|x| x.value).unwrap_or(0))
            .sum();
        let output_value: u64 = self.global.unsigned_tx.output.iter().map(|x| x.value).sum();
        let fee = input_value - output_value;
        let feerate = FeeRate::from_sat_per_vb(
            fee as f32 / (self.clone().extract_tx().get_weight() as f32 / 4.0),
        );
        (Amount::from_sat(fee), feerate)
    }
}
