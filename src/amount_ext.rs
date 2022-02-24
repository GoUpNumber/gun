use std::str::FromStr;

use anyhow::anyhow;
use bdk::bitcoin::{Amount, Denomination};

pub trait FromCliStr: Sized {
    fn from_cli_str(string: &str) -> anyhow::Result<Self>;
}

impl FromCliStr for Amount {
    fn from_cli_str(string: &str) -> anyhow::Result<Self> {
        // check for suffix
        if let Some(value) = parse_suffix(string) {
            return value;
        }
        // parse normal input
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

fn parse_suffix(string: &str) -> Option<Result<Amount, anyhow::Error>> {
    let final_value: f32;
    if void_denominations(string) {
        match string.rfind(char::is_numeric) {
            Some(i) => {
                let user_value = &string[..=i].parse::<f32>().unwrap();
                if check_k(string) {
                    final_value = 1_000 as f32;
                } else if check_m(string) {
                    final_value = 1_000_000 as f32;
                } else {
                    return Some(Err(anyhow!(
                        "'{}' is missing a denomination or a suffix, like k or m",
                        string
                    )));
                }
                return Some(Ok(Amount::from_sat((user_value * final_value) as u64)));
            }
            None => return Some(Err(anyhow!("'{}' is not a Bitcoin amount", string))),
        };
    }
    None
}

fn check_m(string: &str) -> bool {
    string.to_lowercase().contains("m")
}

fn check_k(string: &str) -> bool {
    string.to_lowercase().contains("k")
}

fn void_denominations(string: &str) -> bool {
    !(string.to_lowercase().ends_with("sat") | string.to_lowercase().ends_with("btc"))
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
            Amount::from_cli_str("1.5m").unwrap(),
            Amount::from_sat(1_500_000)
        );
    }
}

