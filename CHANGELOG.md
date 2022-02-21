# CHANGELOG

## v0.6.0

- Add support for signet
- Add support for coldcard bip84 🎉
- Add support for BIP39 passphrases
- Add `--internal` and `--all` flags to `gun address list`
- Add `txos` column to `gun address list`
- Fix `gun split` creating too many address gaps

## v0.5.0

- Upgrade to new bdk commit
- Switch over to using ureq as http backend exclusively

## v0.4.0

- Upgrade to base2048 v2 which removes right-to-left characters which made copy pasting very difficult.
- Less mandatory arguments more prompting when betting.

## v0.3.0

??


## v0.2.0

- Fix unreliable state machine that could cause loss of funds.
