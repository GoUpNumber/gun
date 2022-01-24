use std::str::FromStr;

use anyhow::anyhow;
use bdk::bitcoin::{Amount, Denomination};

pub trait FromCliStr: Sized {
    fn from_cli_str(string: &str) -> anyhow::Result<Self>;
}

impl FromCliStr for Amount {
    fn from_cli_str(string: &str) -> anyhow::Result<Self> {
        let string = string.replace("k", "000").replace("m", "000000").replace(" ", "");
        match string.rfind(char::is_numeric) {
            Some(i) => {
                let denom = Denomination::from_str(&string[(i + 1)..])?;
                let value = String::from_str(&string[..=i])?;
                Ok(Amount::from_str_in(&value, denom)?)
            }
            None => Err(anyhow!("'{}' is not a Bitcoin amount", string)),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_parse_value_btc() {
        assert_eq!(
            Amount::from_cli_str("0.01BTC").unwrap(),
            Amount::from_sat(1_000_000)
        );
    }
    #[test]
    fn test_parse_value_sat() {
        assert_eq!(
            Amount::from_cli_str("100sat").unwrap(),
            Amount::from_sat(100)
        );
    }
    #[test]
    fn test_parse_k_suffix() {
        assert_eq!(
            Amount::from_cli_str("15ksat").unwrap(),
            Amount::from_sat(15_000)
        );
    }
     #[test]
    fn test_parse_m_suffix() {
        assert_eq!(
            Amount::from_cli_str("10msat").unwrap(),
            Amount::from_sat(10_000_000)
        );
    }
}
