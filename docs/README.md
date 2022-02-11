# Go Up Number! &emsp; [![actions_badge]][actions_url]

[actions_badge]: https://github.com/llfourn/gun/workflows/Tests/badge.svg
[actions_url]: https://github.com/llfourn/gun/actions?query=workflow%3ATests

`gun` is a CLI Bitcoin wallet for plebs, degenerates and revolutionaries.
Its distinguishing feature is the ability to do [peer-to-peer betting](https://gun.fun/bet/betting.html).

See [gun.fun](https://gun.fun) for full documentation.

**⚠ WARNING EXPERIMENTAL**

The wallet is alpha quality.
It is buggy and is missing features.
The underlying wallet functionality is built with the awesome [Bitcoin Dev Kit](https://bitcoindevkit.org) but the betting functionality is freshly engineered.
Only put into it what you are willing to lose.
Thanks for testing this for me and thank you in advance for any coins you sacrifice along the way.

## Quick Install

``` sh
git clone https://github.com/LLFourn/gun
cd gun
cargo install --path .
# More efficient version if you have nightly toolchain
cargo -Z avoid-dev-deps install --path .
# Make sure ~/.cargo/bin is in your $PATH
```

The *minimum supported rust version* for `gun` is `1.58.0`.

[BIP84]: https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki
