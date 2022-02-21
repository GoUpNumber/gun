use bdk::{
    bitcoin::{util::psbt::PartiallySignedTransaction as Psbt, Amount},
    FeeRate,
};

pub trait PsbtFeeRate {
    fn fee(&self) -> (Amount, FeeRate, bool);
}

impl PsbtFeeRate for Psbt {
    fn fee(&self) -> (Amount, FeeRate, bool) {
        let mut psbt = self.clone();
        let input_value: u64 = self
            .inputs
            .iter()
            .map(|x| x.witness_utxo.as_ref().map(|x| x.value).unwrap_or(0))
            .sum();

        let mut feerate_estimated = false;
        for input in &mut psbt.inputs {
            if input.final_script_witness.is_none() {
                // FIXME: (Does not work for other script types, taproot)
                input.final_script_witness = Some(vec![vec![0u8; 73], vec![0u8; 33]]);
                feerate_estimated = true;
            };
        }

        let output_value: u64 = psbt.unsigned_tx.output.iter().map(|x| x.value).sum();
        let fee = input_value - output_value;
        let feerate =
            FeeRate::from_sat_per_vb(fee as f32 / (psbt.extract_tx().get_weight() as f32 / 4.0));
        (Amount::from_sat(fee), feerate, feerate_estimated)
    }
}
