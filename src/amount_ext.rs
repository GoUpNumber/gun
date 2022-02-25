use anyhow::anyhow;
use bdk::bitcoin::{Amount, Denomination};
use std::str::FromStr;

pub trait FromCliStr: Sized {
    fn from_cli_str(string: &str) -> anyhow::Result<Self>;
}

impl FromCliStr for Amount {
    fn from_cli_str(string: &str) -> anyhow::Result<Self> {
        match string.rfind(char::is_numeric) {
            Some(i) => {
                let value = &string[..=i].replace('_', "");
                let (amount, shift_right) = match &string[(i + 1)..] {
                    "k" => (Amount::from_str_in(value, Denomination::Bitcoin)?, 100_000),
                    "M" => (Amount::from_str_in(value, Denomination::Bitcoin)?, 100),
                    "" => (Amount::from_str_in(value, Denomination::Satoshi)?, 1),
                    denom => {
                        let denom = Denomination::from_str(denom)?;
                        (Amount::from_str_in(value, denom)?, 1)
                    }
                };

                Ok(amount.checked_div(shift_right).ok_or(anyhow!(
                    "{} has too many decimal places for that denomination",
                    string
                ))?)
            }
            None => Err(anyhow!("'{}' is not a Bitcoin amount", string)),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    #[should_panic(
        expected = "called `Result::unwrap()` on an `Err` value: unknown denomination: kBTC"
    )]
    fn test_parse_failing_btc() {
        Amount::from_cli_str("1kBTC").unwrap();
    }

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
            Amount::from_cli_str("15k").unwrap(),
            Amount::from_sat(15_000)
        );
    }

    #[test]
    fn test_parse_m_suffix() {
        assert_eq!(
            Amount::from_cli_str("1.5M").unwrap(),
            Amount::from_sat(1_500_000)
        );
    }

    #[test]
    fn test_strip_underscores() {
        assert_eq!(
            Amount::from_cli_str("1_000_000").unwrap(),
            Amount::from_sat(1_000_000)
        );
    }

    #[test]
    fn test_strip_underscores_with_denom() {
        assert_eq!(
            Amount::from_cli_str("1_000k").unwrap(),
            Amount::from_sat(1_000_000)
        );
    }
}
