use std::str::FromStr;

use anyhow::anyhow;
use bdk::bitcoin::{Amount, Denomination};

pub trait FromCliStr: Sized {
    fn from_cli_str(string: &str) -> anyhow::Result<Self>;
}

impl FromCliStr for Amount {
    fn from_cli_str(string: &str) -> anyhow::Result<Self> {
        match string.rfind(char::is_numeric) {
            Some(i) => {
                let denom = Denomination::from_str(&string[(i + 1)..])?;
                let value: String = string[..=i]
                    .chars()
                    .filter(|c| !c.is_whitespace())
                    .collect();

                Ok(Amount::from_str_in(&value, denom)?)
            }
            None => Err(anyhow!("{} is not a Bitcoin amount")),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_parse_value() {
        assert_eq!(
            Amount::from_cli_str("0.01BTC").unwrap(),
            Amount::from_sat(1_000_000)
        );
    }
}
