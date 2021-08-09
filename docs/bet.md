# Bet

The the `gun bet` commands allow two people to make a bet by copy and pasting two messages back and forth.
The messages are usually small enough to fit into a single tweet.
An agreed upon oracle decides the outcome.

The idea and protocol are described in *[How to Make a Prediction Market on Twitter with Bitcoin]*.

## Usage

### Add an oracle

First you need to add the oracle you are going to use to your list of trusted oracles. [`h00.ooo`](https://h00.ooo) is the oracle I've set up for this experiment. 
You can explore it at https://outcome.observer/h00.ooo

```sh
gun bet oracle add h00.ooo
```

From here you either have to propose a bet or make an offer:

### Propose a bet

Find an event on [outcome.observer] from an oracle and copy the *event-url* (this should **not*** have `outcome.observer` in it).

```sh
gun bet propose 0.01BTC https://h00.ooo/random/2021-08-11T04:29:00/heads_tails.winner
# ouputs something like:
📣0.01#h00.ooo#/random/2021-08-09T07:00:00/heads_tails.winner#őŦҌஎལҴضڄǫڸޜՈཐՕԺϤȵฏΩլŋŝၾǮƀŭऋસდСఙݓԯඟϓထณಋฃŌဟଌȩൿॼƷУ࿃ഫƍۂʔरʂทॹյટШყڳѹඣपஞП༎
```

This is your proposal.
You can see in plain-text it contains the oracle `h00.ooo` and the event id `/random/2021-08-11T04:29:00/heads_tails.winner`.
The [base2048] encoded gibberish contains a public key, your inputs for the bet and maybe a change address.

**⚠ Since the proposal contains your on on-chain inputs for the bet. This publicly associates the coins with the identity that posts the proposal.**

**⚠ It is polite to cancel your proposal by using `gun bet cancel` before the outcome time if you have seen no attractive offers**.

###  Or Make an offer

Given the above proposal we can make an offer to it. Let's bet on the `heads` outcome. Note you can see the list of outcomes at https://outcome.observer/h00.ooo/random/2021-08-11T04:29:00/heads_tails.winner (but you can guess them from the event url as well).

```sh
gun bet offer 0.01BTC heads 📣0.01#h00.ooo#/random/2021-08-09T06:00:00/heads_tails.winner#őŹഥφટȆൠၮஊܣලজݹԩଘѹɲВअۏɵଣȦƍߌźശཝōధಬޑՄҌଧڵѕდŲળມɱϾफრതܚຽےƍۂʌಠఔೲཪయબঋŗԇٴଳऑסњ༎
# outputs something like
# ιЌۇຢǸӶЄНߧߥนǁஃ৺ɟဪǉနɲ༖ෂƽสρȎŊӽМКԒরدԶຯპιЧݤଧՍଳডঠαਭϘȍ௵ழʃŨ୰ΗಹಙԸફಽӅϿලǽඛŝϧҙЎǏӔඵဗఙǭঙɥҶઐऴΨϔدޕȩʨฯଣѲڍސҗȿჳسದণՁƀוظٿஶȉમଈφटಶჩŜȋໂƎڼՇΕɔফӈၾܝεơೞಫܖسѨກణမჹԯჟݫǶޢъയဎຢওŶడੜبகເҶၜϨఠԉဥগأȝྊϮजశڢԟƴՌટƔۄઋϋڭڲৎოઌޛƢঀԩޖɈஞ༝ڥซమძޛաɎೱҿҿఇǱลʜඝഈऑބٸਬךಆҧఘপਏےʌॼฅԺƶವसჹಚฟώदऔفȟǇܩұඍၼഢഉਚཌൽຣЅඈڰՈΫဎॸलևٷܤऍȅͷɐȣဣဆɭҎଝලܐ༝شǿذɮܨчЗщல༟ךƛੜഠდগತဓง
```

This is your offer.
It can only be read by the person who made the proposal.
It should be indistinguishable from random nonsense.
It contains:

- A public key.
- The outcome you chose to bet on.
- Your inputs and signatures on each input for the bet transaction.
- Maybe a change output

Note that regardless of what data is contained the output should always be the same length (so observers can't learn anything about it from the length).

**⚠Offers last forever. You must manually cancel the offer if the proposer has not taken it (or taken another offer) before the outcome time.**

### Take an offer

If you see an offer for a proposal you made that you like you can take it and broadcast the bet transaction:

```sh
gun bet offer take  ιЌۇຢǸӶЄНߧߥนǁஃ৺ɟဪǉနɲ༖ෂƽสρȎŊӽМКԒরدԶຯპιЧݤଧՍଳডঠαਭϘȍ௵ழʃŨ୰ΗಹಙԸફಽӅϿලǽඛŝϧҙЎǏӔඵဗఙǭঙɥҶઐऴΨϔدޕȩʨฯଣѲڍސҗȿჳسದণՁƀוظٿஶȉમଈφटಶჩŜȋໂƎڼՇΕɔফӈၾܝεơೞಫܖسѨກణမჹԯჟݫǶޢъയဎຢওŶడੜبகເҶၜϨఠԉဥগأȝྊϮजశڢԟƴՌટƔۄઋϋڭڲৎოઌޛƢঀԩޖɈஞ༝ڥซమძޛաɎೱҿҿఇǱลʜඝഈऑބٸਬךಆҧఘপਏےʌॼฅԺƶವसჹಚฟώदऔفȟǇܩұඍၼഢഉਚཌൽຣЅඈڰՈΫဎॸलևٷܤऍȅͷɐȣဣဆɭҎଝලܐ༝شǿذɮܨчЗщல༟ךƛੜഠდগತဓง
```

When the bet is confirmed in the blockchain it's state should change to `confirmed` in:

```sh
gun -s bet list
```

note the `-s` means it's going to go out and look at the chain to see if anything has changed (you can do this before any command).

### Claim your winnings

Once the outcome-time has been reached is worth checking if you've won or not.
A simple way to do this is to do:

```
gun -s bet list
```

Once it's in the `won` state you can do:

```
gun bet claim
```

Note there is no hurry to do this except that while it is in the `won` state but the coins won't be recoverable from your seedwords until you do.
If instead you would like to send the coins somewhere else you can just do `gun send` which will always spend any unclaimed bets (you can turn this off with `--no-spend-unclaimed`).

## Potentially Asked Questions

### Can I recover my bet if I lose my database?

Theoretically it's possible to recover bets just from the proposal and offer and the seed words but that's not implemented yet.

### What privacy is actually guaranteed by this protocol?

Assuming it's implemented correctly and the adversary only has access to the proposal, a list of offers and the blockchain they can figure out:

1. What event the bet was on.
2. Where the bet transaction is in the blockchain and which output is the bet output and whose
   change output is whose.
3. Which inputs belong to the proposer and which belong to the offerer.
4. How much was bet from each party.

They should be unable to determine:

1. Which offer was taken or whether the offer that was taken was in the list of observed offers.
2. Who won the bet (the outcome is public but they don't know who bet on what).

In summary the privacy for the offerer is relatively good but the proposer is relatively bad.

Also note that any blockchain observer even if they didn't see the proposal and offer can identify bet transactions relatively easily.

### Can the privacy be improved?

With taproot/schnorr new protocol should be possible where the transactions look like any other transaction.
This will be very private if done via a direct message.

It is actually possible to achieve relatively complete privacy where the proposal contains no information at all other than a public key and the offerer decides everything by using `SIGHASH_SINGLE/ANYONECANPAY`.
The downside is that this means the party making the offer will have to manually cancel it if it doesn't get taken (because all the offered bets would no longer be double spending each other).

### What if the oracle doesn't attest to the outcome after we've made a bet

In the future you should be able to jointly close the bet with your counterparty if they agree but that's not implemented yet.

### Are there any attacks against this?

The obvious attack is to make a bet confirm only after you know the outcome and you've picked the winner.

To avoid this make sure:

1. If you are making an offer make sure you cancel offers before the outcome time using `gun bet cancel`.
2. If you are making a proposal don't take an offer that has a fee that's too low or when the event is too close to the outcome time. Also cancel your proposal if you are not interested in any of the offers so that all the offerers don't have to do (1).

## Feeback

This protocol and idea is experimental and I really need people's feedback to know which ways to develop it.
Please open an issue on github if you have a question or find a problem.

[How to Make a Prediction Market on Twitter with Bitcoin]: https://raw.githubusercontent.com/LLFourn/two-round-dlc/master/main.pdf
[outcome.observer]: https://outcome.observer
[base2048]: https://github.com/LLFourn/rust-base2048
