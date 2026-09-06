# opendamp

The OpenDAMP covenants and the tool that drives them. OpenDAMP is network
enforcement for a regulated asset on Sequentia: the asset's policy -- who may
hold it, which coins are frozen, how much may move in one transfer, from which
height -- is enforced by Simplicity covenants that every node runs, with no
server in the path of a transfer. This crate holds the covenant programs, the
library that builds and signs transfers under them, and `opendamp`, the
command-line tool an issuer, a holder or a counterparty uses to do so offline.

Two covenants carry the scheme. `C_U(owner)` holds a holder's coins of the
asset; every spend of it must be accompanied by the asset's **verifier**,
`C_V(pi)`, at input 0 of the same transaction, and the verifier is the program
that checks the policy `pi` against every regulated input and output. The
issuer moves the verifier to a new policy with an update, and stops the asset
altogether with a halt. `programs/*.simf` are the programs;
`../doc/sequentia/opendamp-design.md` in the node repository is the design,
and `STATUS.md` here is the record of what is proven against a node.

## Build and test

```sh
cd opendamp
cargo build --release          # target/release/opendamp
cargo test                     # the offline tests: builder, covenants, cosigner
cargo test --test regtest -- --ignored --nocapture   # the proof against a node
```

The regtest proof spawns `sequentiad`: `$OPENDAMP_NODE_BIN`, or
`../../Sequentia/src/sequentiad` beside this checkout.

## The tool

Every command takes `--snapshot FILE`, the policy snapshot: the asset, its
verifier asset and amount `q`, the issuer's update key, the whitelist (bare
keys, or keys with `send_after` and `recv_after` heights), the blacklist of
outpoints, the transfer `limit`, the policy sequence number, and the network.
`examples/snapshot-seq0.json` is one. Nothing needs a node: the snapshot plus
explicit coin data is enough, and what a command prints is broadcast with
`sendrawtransaction`.

| command | what it does |
|---|---|
| `derive --snapshot S [--owner X]...` | the policy's addresses and program identities: `C_V(pi)`, every `C_U(owner)`, the CMRs of the user, verifier and issuer programs, `pi` itself |
| `registry --snapshot S` | the CMR pinning document a wallet or a registrar verifies programs against (`vectors/addresses.json` is the published one) |
| `vectors --snapshot S [--out FILE]` | golden derivation vectors, so an independent implementation can check its taproot construction byte for byte |
| `transfer-build --snapshot S --request R` | an unsigned transfer from a request file, with the sighash of each sender input, the outputs it spends (`prevouts`), and the whitelist proofs resolved -- what a signer that holds the key elsewhere needs |
| `transfer-finalize --snapshot S --request R` | the same transfer built, signed with `sender_privkey` and `fee.privkey` from the request, and every covenant run locally before it is printed |
| `transfer-cosign --snapshot S --transaction T --sender-privkey HEX [--recipient X]... [--out FILE]` | sign the OpenDAMP inputs of a transaction somebody else laid out (below) |
| `issuer-update --snapshot S --next-snapshot S' --request R --issuer-privkey HEX` | move the verifier from policy `S` to policy `S'` |
| `halt --snapshot S --to-spk HEX --request R --issuer-privkey HEX` | send the verifier asset out of the covenant, which stops every transfer of the asset; a halt must burn it (an `OP_RETURN` script), for the reason in the issuer section of `src/txbuild.rs` |

A **request file** (`examples/transfer-request.json`) names the sender's key
and coins, the recipient and amount, the verifier's outpoint, and the fee coin
-- an ordinary asset, since the covenant forbids paying a fee in the regulated
one -- with its key and where its change goes. `locktime` is the height the
transfer claims, which is how a lockup or a receive window is satisfied.
`examples/issuer-request.json` is the issuer's, which needs only the verifier
outpoint and a fee coin.

### Signing a transaction you did not build

A transfer is not always this tool's to lay out. A settlement of a Pignus
repurchase, for one, spends the verifier at input 0 and the lender's `C_U` at
input 2 alongside two coins that are not OpenDAMP's at all, in an order the
bond covenant dictates. `transfer-cosign` owes such a transaction exactly what
the sender owes their own transfer: a signature over each of their `C_U`
inputs, and the verifier witness proving them and every recipient. It touches
nothing else, so a party who signed before the sender loses nothing.

`--transaction T` is a JSON document with `tx`, the transaction's hex, and
`prevouts`, the outputs its inputs spend in input order, each as `{asset,
value, script_pubkey}`; whatever else the document carries comes back with it.
`transfer-build` prints `prevouts` in this form. The candidates for an output
of the asset are every whitelisted key plus any named with `--recipient`.
Before signing, the tool says what it is about to sign -- each coin of the
asset spent from the sender's `C_U`, each output of it and whose `C_U` it
pays, the totals, the height claimed -- and names what a node would only
reject: a verifier of
another policy at input 0, a regulated input that is not the sender's, an
output of the asset paying no candidate's `C_U`, a payment over the limit, a
lockup or receive window the transaction's `nLockTime` does not claim. Every
covenant is run locally before the result is written.

## Layout

```
programs/        the SimplicityHL covenants: user.simf, verifier.simf.in (a
                 template rendered once per transaction shape), issuer.simf
src/programs.rs  compiling and parameterising them; the shape menu
src/txbuild.rs   building, signing and cosigning transfers; issuer operations
src/dmt.rs       the dmt-v1 tree behind the whitelist and blacklist proofs
src/tapscript.rs the taproot construction of C_U and C_V
src/bin/         the opendamp tool
tests/           builder refusals, covenant behaviour, pruning, the cosigner,
                 and the regtest proof
vectors/         the published CMR pinning file
gomirror/        a Go mirror of the dmt-v1 tree, for the policy server
SPEC-dmt-v1.md   the tree's specification
STATUS.md        what is consensus-enforced, proven against a node
```
