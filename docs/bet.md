# Bet

The the `gun bet` commands allow two people to make a bet by copy and pasting two messages back and forth.
The messages are usually small enough to fit into a single tweet.
An agreed upon oracle decides the outcome.

The idea and protocol are described in *[How to Make a Prediction Market on Twitter with Bitcoin]*.

## Usage

### Add an oracle

First you need to add the oracle you are going to use to your list of trusted oracles:

```sh
gun bet oracle add h00.ooo
```

From here you either have to propose a bet or make an offer:

### Propose a bet

Find an event on [outcome.observer] from an oracle (for example `h00.ooo` which is run by me) and copy the *event-url* (this should not have `outcome.observer` in it).

```sh
gun bet propose 0.01BTC https://h00.ooo/random/2021-08-11T04:29:00/heads_tails.winner
# ouputs something like:
📣0.01#h00.ooo#/random/2021-08-09T07:00:00/heads_tails.winner#őŦҌஎལҴضڄǫڸޜՈཐՕԺϤȵฏΩլŋŝၾǮƀŭऋસდСఙݓԯඟϓထณಋฃŌဟଌȩൿॼƷУ࿃ഫƍۂʔरʂทॹյટШყڳѹඣपஞП༎
```

This is your proposal.
You can see in plaintext it contains the oracle `h00.ooo` and the event id `/random/2021-08-11T04:29:00/heads_tails.winner`.
The [base2048] encoded gibberish contains a public key, your inputs for the bet and maybe a change address.

**⚠ Since the proposal contains your on on-chain inputs for the bet. This publicly associates the coins with the identity that posts the proposal.**

###  Or Make an offer

Given the above proposal we can make an offer to it:

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

### Take an offer

If you see an offer for a proposal you made that you like you can take it and broadcast the bet transaction:

```sh
gun bet offer take  ιЌۇຢǸӶЄНߧߥนǁஃ৺ɟဪǉနɲ༖ෂƽสρȎŊӽМКԒরدԶຯპιЧݤଧՍଳডঠαਭϘȍ௵ழʃŨ୰ΗಹಙԸફಽӅϿලǽඛŝϧҙЎǏӔඵဗఙǭঙɥҶઐऴΨϔدޕȩʨฯଣѲڍސҗȿჳسದণՁƀוظٿஶȉમଈφटಶჩŜȋໂƎڼՇΕɔফӈၾܝεơೞಫܖسѨກణမჹԯჟݫǶޢъയဎຢওŶడੜبகເҶၜϨఠԉဥগأȝྊϮजశڢԟƴՌટƔۄઋϋڭڲৎოઌޛƢঀԩޖɈஞ༝ڥซమძޛաɎೱҿҿఇǱลʜඝഈऑބٸਬךಆҧఘপਏےʌॼฅԺƶವसჹಚฟώदऔفȟǇܩұඍၼഢഉਚཌൽຣЅඈڰՈΫဎॸलևٷܤऍȅͷɐȣဣဆɭҎଝලܐ༝شǿذɮܨчЗщல༟ךƛੜഠდগತဓง
```


## Feeback

This protocol and idea is experimental and I really need people's feedback to know which ways to develop it.
Please open an issue if you have a question or find a problem.


[How to Make a Prediction Market on Twitter with Bitcoin]: https://raw.githubusercontent.com/LLFourn/two-round-dlc/master/main.pdf
[outcome.observer](https://outcome.observer)
[base2048](https://github.com/LLFourn/rust-base2048)
