# OpenAMP: issuer-governed assets for Sequentia (design)

OpenAMP governs a regulated asset through a policy server, `openampd`, in this
repository: every holding sits in a 2-of-2 enclave that the holder and the
server's threshold (FROST) policy key must both sign to spend. Confidentiality is
opt-in per transfer, exactly as for any other Sequentia asset. Trustless,
consensus-enforced containment is a different tier with different trade-offs:
it is [OpenDAMP](https://github.com/ConcatenaLabs/opendamp), elected per asset at
issuance; section 8 explains why OpenAMP itself does not take that route.

The end-to-end proofs against a real node are `test/functional/feature_openamp_m0.py`
(enclave issuance, co-signed transfer, freeze, fee conversion, clawback) and
`feature_openamp_daemon.py`, which drives a real `openampd` through registration,
hosted issuance, fee conversion, freeze, velocity, holder caps, clawback, reports
and the anchored transparency log. The README describes the live instance.

Paths such as `src/...`, `test/...` and `contrib/...` are in the
[Sequentia node repository](https://github.com/ConcatenaLabs/Sequentia).

Grounding docs: [`02-open-fee-market.md`](https://github.com/ConcatenaLabs/Sequentia/blob/master/doc/sequentia/02-open-fee-market.md) (any-asset fees, producer whitelists), [`01-architecture.md`](https://github.com/ConcatenaLabs/Sequentia/blob/master/doc/sequentia/01-architecture.md).

---

## 0. One paragraph

OpenAMP is an open-source, self-hostable equivalent of Blockstream's AMP2 for Sequentia: issuers manage regulated assets (securities, funds, bonds) whose every transfer requires co-signature from an issuer-controlled policy server, with KYC whitelisting, categories, velocity limits, vesting, freezing, distributions, clawback, and auditor reports. Restricted assets live only in 2-of-2 taproot outputs (holder key + policy key: the "enclave"); the policy key is a FROST threshold, so freeing the asset requires compromising a quorum of signers, not one machine. The asset ID cryptographically commits to the policy key through the issuance contract hash, so the asset-to-policy binding is verifiable by anyone with no consensus change and no node state. Confidentiality is opt-in per transfer with the same one-flag ease as for any Sequentia asset: the amounts and asset tags are blinded to outside observers, while the policy server holds the blinding keys and therefore always sees who owns what. A restricted asset never appears in a fee output (so it can never leak into a block producer's coinbase); fees ride in an ordinary asset, and a holder who owns only the restricted asset pays through atomic in-transaction fee conversion with the issuer or any registered broker.

---

## 1. Parity target: what AMP2 does

Blockstream AMP manages regulated assets on Liquid, enforced by a co-signing server and a registry of **registered users** (identified by GAID, the Green Account ID). Transfer-restricted assets are held in 2-of-2 multisig; the AMP cosigner refuses to sign any transfer to an unregistered or unauthorized recipient. It supports **categories**, an **issuer authorization endpoint**, **assignments** and **distributions**, **vesting**, **freezing/blacklisting**, **reissuance and burn**, and **reports** (balances, ownership at a block height, proof of transfer and proof of balance). Liquid is confidential by default, so AMP restricted assets are blinded to outside observers while the issuer sees ownership through the registered accounts.

AMP2 (public release targeted Q3 2026) keeps this model and consolidates delivery: issuers no longer run node infrastructure; transaction construction, policy enforcement, investor onboarding, and HSM-backed co-signing are one hosted flow. OpenAMP targets that feature set, open source, on Sequentia.

Where OpenAMP differs from AMP2:

1. **Self-hostable and open-source**: any issuer runs their own policy server; no platform dependency.
2. **Cryptographic asset-to-policy binding**: the asset ID itself commits to the policy key (§3). In AMP the binding between an asset and its cosigner is a platform database row.
3. **Threshold policy key**: the co-signing key is a FROST t-of-n threshold by default, so a single compromised machine cannot sign the asset out of its enclave (§5).
4. **Transparency log**: every policy decision is written to an append-only hash chain whose root is periodically committed on-chain, so issuers and regulators can audit the server after the fact (§6).
5. **Fee flexibility**: because Sequentia fees can be paid in any accepted asset by any party, users can pay in the restricted asset itself (issuer bridges to the fee market atomically) or the issuer can sponsor the fee (§7). AMP2 on Liquid cannot: L-BTC is mandatory there.
6. **Confidential-optional on a transparent chain**: Sequentia is transparent by default (a deliberate flip from Liquid), so confidentiality is opt-in per transfer. OpenAMP makes that opt-in as easy for a restricted asset as for any other (§4).

---

## 2. Chain facts this design stands on

Verified in the current tree:

- **Fee outputs** are Elements explicit fee outputs: empty `scriptPubKey`, explicit value, explicit asset (`CTxOut::IsFee()`, `src/primitives/transaction.h:328`). Mempool acceptance requires exactly one fee asset per transaction (`src/validation.cpp:951-960`, `bad-txns-multiple-fee-assets`).
- **The per-node fee-asset whitelist is default-deny**: the `ExchangeRateMap` (`src/exchangerates.h:25`) converts fee value; an asset not explicitly listed converts to 0, so the transaction is non-paying and never mined by that producer (`src/exchangerates.cpp:24-37`). A restricted asset is never listed.
- **Coinbase outputs are consensus-pinned to the leader**: from `pos_coinbase_leader_height`, every value-bearing coinbase output must equal `PosLeaderFeeScript(leader)` (`bad-coinbase-not-leader`, `src/validation.cpp:2548-2559`). Coinbase may not contain fee outputs (`bad-cb-fee`, `src/consensus/tx_check.cpp:60-64`). No subsidy, no coinbase issuance (`genesis_subsidy = 0`).
- **Asset IDs commit to a contract hash**: entropy `E = H(H(prevout) || contract_hash)`, `asset = H(E || 0)`, reissuance token `= H(E || 1)` (`src/issuance.cpp:23-64`). `issueasset` accepts `contract_hash` and `denomination`.
- **Transparent by default, confidential opt-in**: `m_default_blinded_addresses = false` (`src/chainparams.cpp:504/760`); any output can carry a blinding nonce, and Elements allows blinding the asset and value independently. Confidential (blinded) addresses use the blech32 HRP; the node's PSET/`rawblindrawtransaction` RPCs build the rangeproofs and surjection proofs.
- **PSET (Elements PSBT v2) RPCs exist end to end**: `createpsbt`, `walletcreatefundedpsbt`, `walletprocesspsbt`, `combinepsbt`, `finalizepsbt`, `analyzepsbt`, `decodepsbt`, `rawblindrawtransaction`.

---

## 3. Genesis anchor without consensus: the contract commitment

Elements already gives a genesis-anchored, stateless registry: the asset ID is a hash commitment to the issuance contract. OpenAMP defines a canonical contract JSON extending the `sequentia-registry` entry format:

```json
{
  "name": "Example Bond 2027",
  "ticker": "BONDX",
  "precision": 8,
  "issuer_pubkey": "<33-byte or 32-byte x-only hex>",
  "version": 0,
  "openamp": {
    "version": 1,
    "type": "restricted",             // "restricted" | "tracked"
    "policy_pubkey": "<32-byte x-only hex>",   // the FROST group public key
    "clawback": true,                 // clawback leaf present in the enclave tree
    "burn_allowed": true,             // OP_RETURN burns permitted
    "policy_endpoints": ["https://amp.example-issuer.com"],
    "terms_hash": "<sha256 of legal terms>"
  }
}
```

The contract never records confidentiality, which is chosen per transfer (§4). Assets issued before that rule carry a `confidential` key in their frozen contract bytes and verify as they are, because the asset id commits to those exact bytes.

`contract_hash = sha256(canonical-json)` is passed to `issueasset`/`rawissueasset`, so `asset_id` commits to `policy_pubkey`, the clawback terms, and whether the asset is confidential. Anyone holding the contract JSON (served by the registry and the policy server) verifies the binding offline by recomputing the entropy chain. Wallets refuse to treat an asset as an OpenAMP asset unless this verification passes. No consensus lookup table, no state bloat, no protocol change; full nodes remain oblivious.

Holder terms are fixed and disclosed at issuance: whether clawback exists, whether burns are allowed, whether the asset is confidential. An issuer cannot quietly change them later (a new policy key, or a change of any committed field, means a new asset ID).

---

## 4. Confidentiality (opt-in, equal to any asset)

Sequentia is transparent by default and confidentiality is opt-in per output; OpenAMP makes that opt-in as easy for a restricted asset as for an ordinary one. An asset is never "a confidential asset": any holder may receive or move any restricted asset confidentially in a given transfer (`"confidential": true` on `POST /v1/transfers`). When a transfer is confidential:

- The recipient's enclave address is the **blech32 confidential taproot address**: the same 2-of-2 taproot output (§5) plus a blinding public key in the output nonce. The address endpoint returns it with `confidential=1`, alongside the unblinded form.
- Amounts and asset tags are **blinded to outside observers**. The chain shows enclave outputs with committed values; an outsider cannot read who holds how much, nor even that a given output carries the restricted asset.
- The **policy server holds the blinding keys** and therefore always sees who owns what. This is required for it to scan balances, enforce velocity limits and holder caps, and produce ownership and proof-of-balance reports. The holder learns the blinding key for their own outputs (to know their balance and to spend); the server learns it for every output (that is the point). Blinding-key distribution is part of the enclave-address handshake, not a separate disclosure step.
- Transfers are constructed and blinded through the node's tested CT machinery, then policy-checked and co-signed, so no confidential-transaction crypto is reimplemented in `openampd`. Implementation approach, confirmed feasible on regtest against the real node:
  - `openampd` derives a per-holder-per-asset blinding key, builds the confidential enclave address (the enclave taproot scriptPubKey plus that blinding public key), and returns it from the address endpoint. Blinding succeeds with the standard requirement of at least two confidential outputs per transaction (Elements refuses to blind a lone output), which every transfer satisfies (recipient plus change, or plus the conversion output).
  - The server keeps the blinding keys in a node watch wallet (`importaddress` + `importblindingkey` on each confidential enclave address). That wallet's `listunspent` reports unblinded balances for scanning and reports, and `rawblindrawtransaction` / `unblindrawtransaction` run against it unblind the enclave inputs and blind the outputs during a transfer. The holder still just signs the returned sighashes; no blinding knowledge is needed on the wallet side.

The honest limit, stated in the UI: a confidential transfer of a restricted asset is confidential against third parties, never against the issuer or its policy server. That is the correct property for a regulated instrument (the issuer must be able to know who owns what at any time), and it is exactly AMP2's model on Liquid. It is narrower than a normal Sequentia confidential address, where nobody but the counterparties sees the amount.

An enclave can hold explicit and blinded coins side by side, and every read the server serves (balances, holders, supply) unifies both views. Issuance can blind its own mint transaction (`"confidential": true` on the issue request), which marks nothing about the asset or its later transfers. `test/functional/feature_openamp_confidential.py` proves the whole path on regtest: blinded transfers on chain, exact unblinded balances from the server's watch wallet, and fee conversion inside a confidential transfer. The issuer's funding wallet needs no `-blindedaddresses` setting; every Sequentia wallet can produce blinded change per call.

---

## 5. The enclave: addresses and keys

Every restricted-asset UTXO pays to a taproot output with **internal key = NUMS** (the BIP341 nothing-up-my-sleeve point, so no key-path spend) and a script tree of:

- **L_user** (per holder): `<K_user> OP_CHECKSIGVERIFY <K_policy> OP_CHECKSIG`, the co-signed transfer leaf. `K_user` is derived from the holder's registered account key; `K_policy` is the asset-wide policy key from the contract.
- **L_claw** (default ON, opt-out via `"clawback": false`): `<K_issuer> OP_CHECKSIGVERIFY <K_policy> OP_CHECKSIG`. Issuer plus policy, no user key: court-ordered seizure, lost-key recovery, estate execution. Its presence is committed in the contract hash, so holders accept it knowingly at purchase. Without it, lost keys mean provable-burn-then-reissue.

Key structure and reasons:

- **The policy key is a FROST threshold.** On-chain it is a single x-only point `K_policy` (the FROST group public key). Off-chain, signing under it requires a t-of-n quorum of policy signers. Recommended deployment: 2-of-3 across the issuer plus two jurisdictionally separated operators, so no single machine compromise can co-sign the asset out of its enclave and no single loss bricks the asset. This is the primary defense: the enclave is a 2-of-2 (holder + policy), and "the policy side" is itself a threshold. `openampd` produces BIP340-compatible threshold Schnorr signatures that verify under `K_policy` (§6). The signing engine sits behind a signer interface (single software key for the testnet demo, FROST quorum in production).
- **Script-path 2-of-2, not MuSig2 key-path.** Plain `CHECKSIGVERIFY` chains are simple for every wallet (SWK, Ambra, hardware later) and make co-signing a one-round PSET exchange. The FROST ceremony happens entirely on the policy side to produce the single `K_policy` signature; the holder just signs `K_user`.
- **Account IDs.** The GAID analog is the **AID**: a hash of the holder's registered account key. Registration = KYC dossier + AID + key. Because the server knows every account key it derives every enclave address, which is what makes ownership reports exact (and, for confidential assets, why it holds the blinding keys).

Server-continuity (open dial, default OFF): an optional inactivity-timeout recovery leaf lets funds move if the policy quorum is permanently gone. Default is no such leaf and reliance on the threshold key; per-asset choice, disclosed in the contract.

---

## 6. The policy server: `openampd`

A Go daemon, deployed like our other services. Modules:

- **Chain follower**: tracks the chain via `sequentiad` RPC, anchor-aware; all stateful accounting keys on (block hash, Bitcoin-anchor depth) and rolls back on reorgs, per anchoring supremacy. Velocity windows and snapshot heights are measured in anchor-confirmed blocks; co-sign decisions are idempotent.
- **Registry of record**: registered users (AID, account key, KYC dossier reference, jurisdiction tags, categories), assets (contract JSON, policy rules), assignments, vesting schedules, freeze lists. For confidential assets it also holds the blinding keys.
- **Policy engine**: a declarative per-asset policy document evaluated on every co-sign request: recipient registered and in an allowed category; sender not frozen; UTXOs not frozen; velocity limits; holder cap (exact from full address derivation); vesting; lock-in periods; jurisdiction rules; optional forwarding to an issuer authorization endpoint.
- **Co-signing engine**: input is a PSET plus transfer metadata; it independently re-derives every claim from the PSET (never trusts metadata), unblinding confidential outputs with the server-held keys: all restricted inputs are enclave UTXOs of the claimed sender, all restricted outputs pay enclave scripts of registered recipients or permitted burns, no restricted fee output, fee asset not restricted. Then policy engine, then sign `K_policy` for each restricted input via the signer interface (software key for the demo, FROST quorum in production), return the PSET.
- **Threshold signer (FROST)**: produces BIP340-compatible threshold Schnorr signatures under the group key `K_policy`. A signing request fans out to the quorum, which return signature shares that aggregate to a single 64-byte signature verifying under `K_policy` in the enclave's `OP_CHECKSIG`. Key generation is a one-time DKG per asset; the group public key becomes the asset's `policy_pubkey`. For the testnet demo `openampd` runs a single in-process key behind the same interface.
- **Transparency log**: every decision (co-sign granted/refused, freeze, clawback, registration change) appends to a hash-chained log; the head is committed on-chain in an `OP_RETURN` periodically. Regulators and issuers can replay and verify the server never rewrote history.
- **APIs** (REST, token/mTLS): issuer surface (users, categories, assets, assignments, distributions, freezes, clawback, reports) and wallet surface (register account, get enclave receive address for an AID, request co-sign, query policy and own limits).

Freeze: user-freeze and UTXO-freeze are server-side refusals; global asset freeze halts co-signing. Clawback is a deliberately heavyweight ceremony (dual authorization, transparency-log entry with reason code before signing, spend via `L_claw` into a designated issuer enclave address). Distributions: ownership snapshot at an anchor-confirmed height, then batch payments of an ordinary asset to holders, reconciled against entitlement, vesting-aware.

---

## 7. Fees for restricted-asset transfers

A restricted asset never appears in a fee output, so it can never enter the floating fee pool or a coinbase. This is enforced by the wallet (never selects it as fee asset), the policy server (refuses to co-sign any transaction with a fee output in the restricted asset), and Sequentia's default-deny producer whitelist (a fee in an unlisted asset is non-paying, and no producer would whitelist an asset it is not KYC'd to receive). The fee output is always in an ordinary asset. Three ways to fund it:

- **Self-paid**: the sender's wallet adds ordinary-asset fee inputs plus the fee output and change. The issuer is not involved.
- **Fee conversion** (for senders who hold only the restricted asset): one atomic transaction where the issuer (or any registered broker) receives a fee-equivalent slice of the asset into its own enclave account and attaches the real fee in an ordinary asset. Atomicity is inherent (the sender's signatures cover the conversion output, the issuer's signature covers the fee input); the sender approves the quoted rate by signing. Self-funding, not a subsidy. Rate published at the policy endpoint, quoted before signing, displayed in the asset's own units.
- **Sponsored**: fee conversion with no conversion output; the issuer eats the tiny fee.

One fee asset per transaction is a mempool rule, so converter and sender never both attach fees.

---

## 8. Rejected alternatives

- **Consensus-level asset-bound covenants (an externally drafted proposal)**: rejected. It breaks stateless UTXO validation (every node maintains an indexed issuance-commitment database, the state bloat the memo concedes); it is consensus-incompatible with Sequentia (`bad-coinbase-not-leader` pins every value-bearing coinbase output to the leader's fee script); KYC'd block producers fragment the open fee market; and it solves a problem that "never a fee output" dissolves. Consensus surface is our scarcest resource; a compliance feature must not add reorg-relevant code paths.
- **A consensus-enforced containment covenant**: a Tapscript covenant could make containment trustless (survive a fully compromised policy server), but it must read each output's asset tag in-script, so it forces all-explicit outputs and cannot work over confidential ones (identifying a blinded output's asset needs either revealing it or a zero-knowledge proof tapscript can't verify). That publishes every holding to outside observers. For a regulated asset the requirement is the opposite (issuer sees all, outsiders see nothing), so this is rejected; the threshold policy key (§5) instead raises the "compromised server" bar without going transparent.
- **Pure-covenant compliance (no server)**: KYC, velocity, holder caps, and vesting are inherently off-chain facts; the server stays.
- **Omnibus enclave (single asset-wide address, server-side ledger)**: makes the server custodial; rejected because user keys must be required for every move (non-custodial 2-of-2 is the AMP property worth keeping).

---

## 9. Design principle: confidentiality over trustless containment

The requirement for a regulated instrument is that the issuer (and its policy server) can know who owns what at any time while outside observers cannot. Given current Sequentia primitives, at most two of these three hold at once: no-trusted-party containment, outsider-confidentiality, and a trusted-but-threshold-hardened server. OpenAMP takes outsider-confidentiality plus a FROST-hardened server (exactly AMP2's model), so freeing the asset needs a quorum rather than one machine. This matches the first principle that Sequentia flipped Liquid's confidential-by-default to transparent-by-default: privacy for a governed asset is an opt-in the issuer chooses, bounded by what the policy server must see.

---

## 10. Wallet and ecosystem integration (built)

- **Sequentia Core** (`getopenampaccount`, `signopenamptransfer`, the GUI's OpenAMP tab): the holder's side, described for holders in [`openamp-holder.md`](https://github.com/ConcatenaLabs/Sequentia/blob/master/doc/sequentia/openamp-holder.md). The account id and the enclave are derived offline from public keys, so a holder can check that the address they are paid at is the one the asset's own id implies rather than trusting the server to say. Signing recomputes each sighash from the transaction and refuses any that does not match what the server asked for, which the other wallets cannot do because they have no chain to check against. Core does not speak to the policy server itself: the Qt build carries no TLS backend, so the https half is left to whatever already has one.
- **SWK web wallet** (`/wallet`): a managed-assets flow per issuer server: register the account key as an AID, restricted-asset balance rows rendered as ordinary rows (SEQ-equal-standing: no privileged labels), enclave receive address, and send through `/openamp/v1/transfers` with on-device schnorr signing of the returned sighashes. Fails soft if the policy server is unreachable.
- **Ambra** (v0.10.3): the same flows over a Rust FFI schnorr signer (`openamp_xonly_pubkey` / `openamp_sign_sighash`, BIP32 `m/5/0`).
- **Registry** (`sequentia-registry`): serves the `openamp` block (policy key, clawback, policy endpoints) for discovery; accepts x-only issuer keys. Wallets verify the asset-to-policy binding by fetching the contract from the policy server and recomputing the asset id.
- **Explorer** (nice-to-have, not built): badge OpenAMP assets, show the clawback flag and policy endpoints, render enclave outputs as "restricted (issuer-governed)".
- **SeqDEX** (later): restricted assets trade only between registered users; the settlement PSET gets the policy co-sign like any transfer.

For a confidential receive, the wallet shows the blech32 enclave address: its normal confidential toggle applies to restricted assets too, with UI copy that is honest the issuer still sees the amount.

---

## 11. Where each part is proven

Against a real node on regtest, in the node repository's `test/functional/`:

- `feature_openamp_m0.py`: contract hashing, issuance into enclave addresses, asset ids recomputed independently and accepted by consensus, co-signed transfers, freeze by refusal, fee conversion, clawback.
- `feature_openamp_daemon.py`: a real `openampd` through registration, per-asset policy, co-signing, hosted issuance, fee conversion, freeze, velocity, holder caps, clawback, ownership reports and the anchored transparency log.
- `feature_openamp_confidential.py`: opt-in confidential transfers end to end (blech32 enclave addresses, watch-wallet blinding keys, blinded co-signing).

In this repository, `go test ./...` covers the policy engine, the Elements primitives against golden vectors, and the FROST 2-of-3 backend (distributed key generation and signing). OpenAMP needs no change to the chain.
