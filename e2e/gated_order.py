#!/usr/bin/env python3
"""The gated order through a real openampd against a real node.

    SEQUENTIA_REPO=~/Sequentia OPENAMPD=./openampd/openampd \\
    TOKEN_COVENANTS=<sequentia-contracts>/tools/token-covenants/target/release/token-covenants \\
    python3 e2e/gated_order.py

A holder's resting offer to sell a restricted asset on the chain, filled while
its maker is offline. The order wraps SeqDEX's real fill covenant behind the
policy key; a node on a custom chain with -par=1 judges every script, and every
negative case below is forced into a block with generateblock.

The seller places, in one transaction it co-signs as its own move, a gated
order of 500 atoms (1,000 fee-asset atoms each, at least 10 a fill) and a swap
HTLC of 100 atoms; it also rests an ordinary SeqDEX bid for the asset into its
own enclave. Then:

  1. the order openampd admitted is the one built here from the terms alone;
  2. openampd refuses a fill without the broadcast (400), a fill to an
     account the asset's rules do not admit (403 category), and a fill that
     also spends the seller's HTLC (403); it fills 100 atoms for an approved
     buyer, co-signing and broadcasting in one step: mined, the remainder of
     400 at the order's script;
  3. in blocks: a fill without the policy signature, and a fill that reuses the
     policy signature of the mined fill, are refused; so is the refund before
     the expiry;
  4. at the expiry openampd refuses to fill (403 expired); the issuer freezes
     the seller and openampd is STOPPED;
  5. the keyless refund refuses in blocks to go anywhere but home: another
     enclave, one atom short, home at output 1, input 1;
  6. the collision matrix: the order's refund against the HTLC's refund (both
     orders of inputs) and against the seller's resting bid (the refund at
     input 2 as the bid's payment at output 2, and at input 0 beside the bid);
     each refused in a block;
  7. the remainder of 400 goes home to the seller's enclave, keyless, mined.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.dont_write_bytecode = True

import swap_htlc as base  # noqa: E402
from swap_htlc import (  # noqa: E402
    FEE, HOUR, ISSUER_TOKEN, NONFINAL, NUMS, REPO, control, fill_leaf, htlc_tap, sender_sig, sized,
)
from test_framework.key import compute_xonly_pubkey, generate_privkey, sign_schnorr  # noqa: E402
from test_framework.messages import CTransaction, CTxIn, CTxOut, CTxOutAsset, CTxOutValue, sha256, tx_from_hex  # noqa: E402
from test_framework.script import (  # noqa: E402
    CScript, OP_0, OP_1, OP_CHECKLOCKTIMEVERIFY, OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_DROP, OP_EQUAL,
    OP_EQUALVERIFY, OP_INSPECTINPUTVALUE, OP_INSPECTOUTPUTASSET, OP_INSPECTOUTPUTSCRIPTPUBKEY,
    OP_INSPECTOUTPUTVALUE, OP_PUSHCURRENTINPUTINDEX, OP_RETURN, taproot_construct,
)

ORDER = 500
PRICE = 1000  # fee-asset atoms per atom of the restricted asset
MIN_LOT = 10
HTLC = 100


def gated_tap(policy_x, fill, issuer_x, expiry, maker_prog, asset):
    leaves = [("fill", CScript(bytes(CScript([policy_x, OP_CHECKSIGVERIFY])) + fill)),
              ("refund", CScript([expiry, OP_CHECKLOCKTIMEVERIFY, OP_DROP,
                                  OP_PUSHCURRENTINPUTINDEX, OP_0, OP_EQUALVERIFY,
                                  OP_0, OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_1, OP_EQUALVERIFY, maker_prog, OP_EQUALVERIFY,
                                  OP_0, OP_INSPECTOUTPUTASSET, OP_1, OP_EQUALVERIFY, asset, OP_EQUALVERIFY,
                                  OP_0, OP_INSPECTOUTPUTVALUE, OP_1, OP_EQUALVERIFY,
                                  OP_0, OP_INSPECTINPUTVALUE, OP_1, OP_EQUALVERIFY, OP_EQUAL]))]
    if issuer_x:
        leaves.append(("claw", CScript([issuer_x, OP_CHECKSIGVERIFY, policy_x, OP_CHECKSIG])))
    return taproot_construct(NUMS, leaves)


class GatedOrderE2E(base.SwapHTLCE2E):
    def set_test_params(self):
        super().set_test_params()

    def run_test(self):
        super().run_test()

    def with_daemon(self):
        node = self.node
        self.w = node.get_wallet_rpc(self.default_wallet_name)
        self.miner = self.w.getnewaddress("", "bech32")
        import time
        for _ in range(200):
            try:
                self.api("GET", "/v1/assets")
                break
            except (ConnectionRefusedError, OSError):
                time.sleep(0.1)
        keys, x, aids = {}, {}, {}
        for who in ("seller", "buyer", "other", "issuer"):
            keys[who] = generate_privkey()
            x[who] = compute_xonly_pubkey(keys[who])[0]
            aids[who] = self.api("POST", "/v1/users", {"pubkeys": [x[who].hex()]})[1]["aid"]
        _, res = self.api("POST", "/v1/issuer/assets", {
            "name": "Gated Bond", "ticker": "GATEB", "precision": 0, "atoms": 1000, "clawback": True,
            "holder_aid": aids["seller"], "issuer_aid": aids["issuer"], "supply_cap": 1000,
        }, token=ISSUER_TOKEN)
        asset = res["asset"]
        self.mine()
        self.A = bytes.fromhex(asset)[::-1]
        for who in ("seller", "buyer"):
            self.api("POST", "/v1/issuer/categories", {"aid": aids[who], "categories": ["kyc:eu"]}, token=ISSUER_TOKEN)
        self.api("POST", "/v1/issuer/rules", {"asset": asset, "rules": {"allowed_categories": ["kyc:eu"]}}, token=ISSUER_TOKEN)
        a = self.api("GET", "/v1/assets/" + asset)[1]
        policy_x, issuer_x = bytes.fromhex(a["policy_pub"]), bytes.fromhex(a["issuer_pub"])
        addr = {w: self.api("GET", "/v1/users/%s/address?asset=%s" % (aids[w], asset))[1] for w in ("seller", "buyer", "other")}
        enclave = {w: bytes.fromhex(addr[w]["script_pubkey"]) for w in addr}
        seller_prog = enclave["seller"][2:]
        scan = node.scantxoutset("start", ["raw(%s)" % addr["seller"]["script_pubkey"]])
        coin = [u for u in scan["unspents"] if u["asset"] == asset][0]
        seller_coin = self.coin_at(coin["txid"], coin["vout"])

        # The order: SeqDEX's fill covenant, selling the asset for the fee
        # asset, paying the maker at a taproot program of its own.
        maker_payout = x["seller"]
        fill = fill_leaf(self.A, self.BTC, PRICE, 1, MIN_LOT, maker_payout)
        expiry = self.now + 3 * HOUR
        order = gated_tap(policy_x, fill, issuer_x, expiry, seller_prog, self.A)
        secret = sha256(b"gated e2e secret")
        H = sha256(secret)
        htlc = htlc_tap(H, x["buyer"], policy_x, issuer_x, expiry, seller_prog, self.A, HTLC)
        # The seller's ordinary SeqDEX bid for the asset, into its enclave.
        bid_leaf = fill_leaf(self.BTC, self.A, 1, 1000, 1000, seller_prog)
        bid_tap = taproot_construct(NUMS, [("fill", CScript(bid_leaf)),
                                           ("refund", CScript([expiry + 10 * HOUR, OP_CHECKLOCKTIMEVERIFY, OP_DROP, x["seller"], OP_CHECKSIG]))])
        BID = self.fund_order(bid_tap.scriptPubKey, self.BTC, 1000000)

        # -- placement ---------------------------------------------------------------
        outs = [self.asset_out(order.scriptPubKey, ORDER), self.asset_out(htlc.scriptPubKey, HTLC),
                self.asset_out(enclave["seller"], 1000 - ORDER - HTLC)]
        place, spent = self.with_fee([seller_coin], outs)
        _, cs = self.api("POST", "/v1/cosign", {
            "tx": place.serialize().hex(), "asset": asset, "sender_aid": aids["seller"], "inputs": [0],
            "sender_sig": sender_sig(keys["seller"], place),
            "order_outputs": [{"output": 0, "fill": fill.hex(), "expiry": expiry}],
            "htlc_outputs": [{"output": 1, "buyer_aid": aids["buyer"], "hash": H.hex(), "t_seq": expiry}],
        })
        entry = cs["sigs"][0]
        place.wit.vtxinwit[0].scriptWitness.stack = [bytes.fromhex(entry["policy_sig"]),
                                                     sign_schnorr(keys["seller"], bytes.fromhex(entry["sighash"])),
                                                     bytes.fromhex(entry["leaf"]), bytes.fromhex(entry["control"])]
        place_txid = node.sendrawtransaction(place.serialize().hex())
        self.mine()
        placed = tx_from_hex(node.getrawtransaction(place_txid))
        # 1. the server's order is the one built here from the terms alone.
        assert bytes(placed.vout[0].scriptPubKey) == bytes(order.scriptPubKey)
        ORD = self.coin_at(place_txid, 0)
        HT = self.coin_at(place_txid, 1)
        self.rec("placement", {"txid": place_txid, "vsize": node.getrawtransaction(place_txid, True)["vsize"],
                               "order_spk": bytes(order.scriptPubKey).hex(),
                               "leaf_bytes": {n: len(order.leaves[n].script) for n in ("fill", "refund", "claw")}})

        # -- 2. fills ------------------------------------------------------------------
        def fill_tx(to, n, coin=ORD, at=1, left=None):
            """A taker's fill of n atoms: its fee coin at input 0, the order at
            input `at` (credit at 2*at, remainder at 2*at+1)."""
            fc = self.fee_coin()
            left = ORDER - n if left is None else left
            pay = n * PRICE
            tx = CTransaction()
            tx.nVersion = 2
            ins = [fc[0], coin[0]] if at == 1 else [coin[0], fc[0]]
            tx.vin = [CTxIn(op, nSequence=NONFINAL) for op in ins]
            change = self.btc_out(self.spk(), fc[1].nValue.getAmount() - pay - FEE)
            credit = self.btc_out(CScript([OP_1, maker_payout]), pay)
            rem = self.asset_out(order.scriptPubKey, left)
            got = self.asset_out(to, n)
            fee = CTxOut(CTxOutValue(FEE), b"", CTxOutAsset(b"\x01" + self.BTC))
            tx.vout = [got, change, credit, rem, fee] if at == 1 else [credit, rem, got, change, fee]
            tx = sized(tx_from_hex(self.w.signrawtransactionwithwallet(sized(tx).serialize().hex())["hex"]))
            return tx, ([fc[1], coin[1]] if at == 1 else [coin[1], fc[1]])

        def ask(tx, idx=1, broadcast=True, expect=None):
            body = {"tx": tx.serialize().hex(), "asset": asset, "sender_aid": aids["seller"], "order_inputs": [{"input": idx}]}
            if broadcast:
                body["broadcast"] = True
            return self.api("POST", "/v1/cosign", body, expect=expect)

        tx, _ = fill_tx(enclave["buyer"], 100)
        st, body = ask(tx, broadcast=False)
        assert st == 400 and "broadcast" in body["error"], body
        tx2, _ = fill_tx(enclave["other"], 100)
        st, body = ask(tx2)
        assert st == 403 and "category" in body["error"], body
        self.rec("server_refusals", {"without_broadcast": "400", "to_an_account_without_the_category": body})
        # A fill that also spends the seller's HTLC is refused before any signature.
        both = CTransaction()
        both.nVersion = 2
        both.vin = list(tx.vin) + [CTxIn(HT[0], nSequence=NONFINAL)]
        both.vout = list(tx.vout) + [self.asset_out(enclave["buyer"], HTLC)]
        st, body = ask(sized(both))
        assert st == 403 and "no other coin of the asset" in body["error"], body

        _, body = ask(tx)
        fill_txid = body["txid"]
        self.mine()
        mined = node.getrawtransaction(fill_txid, True)
        assert mined["confirmations"] >= 1
        filled = tx_from_hex(node.getrawtransaction(fill_txid))
        assert bytes(filled.vout[3].scriptPubKey) == bytes(order.scriptPubKey) and filled.vout[3].nValue.getAmount() == ORDER - 100
        REM = self.coin_at(fill_txid, 3)
        self.rec("fill", {"txid": fill_txid, "vsize": mined["vsize"], "buyer_gets": 100, "maker_gets": 100 * PRICE,
                          "remainder_at_the_order": ORDER - 100})

        # -- 3. in blocks: no fill without this server -----------------------------------
        fl = order.leaves["fill"].script
        tx, sp = fill_tx(enclave["buyer"], 50, coin=REM, left=ORDER - 150)
        tx.wit.vtxinwit[1].scriptWitness.stack = [sign_schnorr(keys["buyer"], self.sighash(tx, sp, 1, fl)), bytes(fl), control(order, "fill")]
        self.refuse("fill without the policy signature (the buyer's in its place)", tx, "Invalid Schnorr signature")
        tx, sp = fill_tx(enclave["buyer"], 50, coin=REM, left=ORDER - 150)
        tx.wit.vtxinwit[1].scriptWitness.stack = [filled.wit.vtxinwit[1].scriptWitness.stack[0], bytes(fl), control(order, "fill")]
        self.refuse("fill reusing the policy signature of the mined fill", tx, "Invalid Schnorr signature")
        early = self.refund_tx([REM], [self.asset_out(enclave["seller"], ORDER - 100)], order, expiry)
        self.refuse("refund before the expiry", early, "non-final")

        # -- 4. the expiry; freeze the seller; stop the server ------------------------
        self.jump_to(expiry + 60)
        tx, _ = fill_tx(enclave["buyer"], 50, coin=REM, left=ORDER - 150)
        st, body = ask(tx)
        assert st == 403 and "expired" in body["error"], body
        self.rec("fill_after_expiry", body)
        self.api("POST", "/v1/issuer/freeze", {"aid": aids["seller"], "frozen": True}, token=ISSUER_TOKEN)
        self.proc.terminate()
        self.proc.wait(timeout=10)

        # -- 5. the refund goes only home ----------------------------------------------
        homeout = self.asset_out(enclave["seller"], ORDER - 100)
        self.refuse("order refund to another enclave", self.refund_tx([REM], [self.asset_out(enclave["other"], ORDER - 100)], order, expiry),
                    "Script failed an OP_EQUALVERIFY operation")
        self.refuse("order refund one atom short", self.refund_tx([REM], [self.asset_out(enclave["seller"], ORDER - 101),
                                                                       self.asset_out(enclave["other"], 1)], order, expiry),
                    "Script evaluated without error but finished with a false/empty top stack element")
        self.refuse("order refund home at output 1", self.refund_tx([REM], [CTxOut(CTxOutValue(0), CScript([OP_RETURN]), CTxOutAsset(b"\x01" + self.BTC)), homeout], order, expiry),
                    "Script failed an OP_EQUALVERIFY operation")
        self.refuse("order refund at input 1", self.refund_tx([REM], [CTxOut(CTxOutValue(0), CScript([OP_RETURN]), CTxOutAsset(b"\x01" + self.BTC)), homeout], order, expiry, fee_first=True),
                    "Script failed an OP_EQUALVERIFY operation")

        # -- 6. the collision matrix ------------------------------------------------------
        matrix = []

        def collide(label, tx, reason):
            self.refuse(label, tx, reason)
            matrix.append({"case": label, "refused": reason})
        hhome = self.asset_out(enclave["seller"], HTLC)
        rwo = [bytes(order.leaves["refund"].script), control(order, "refund")]
        rwh = [bytes(htlc.leaves["refund"].script), control(htlc, "refund")]
        collide("order refund at 0 and HTLC refund at 1",
                self.spend_with([(REM, rwo), (HT, rwh)], [homeout, hhome], expiry), "Script failed an OP_EQUALVERIFY operation")
        collide("HTLC refund at 0 and order refund at 1",
                self.spend_with([(HT, rwh), (REM, rwo)], [hhome, homeout], expiry), "Script failed an OP_EQUALVERIFY operation")
        # The order's refund at input 2 as the payment of the seller's bid at
        # input 1 (credit at output 2): 400 atoms would buy 400,000 for nothing.
        got = (ORDER - 100) * 1000
        c = self.fee_coin()
        taker = self.spk()
        fee_out = CTxOut(CTxOutValue(FEE), b"", CTxOutAsset(b"\x01" + self.BTC))
        collide("order refund at input 2 as the payment of the seller's bid at input 1 (output 2)",
                self.spend_raw([(c, None), (BID, [bid_leaf, control(bid_tap, "fill")]), (REM, rwo)],
                               [self.btc_out(taker, c[1].nValue.getAmount() - FEE + got), fee_out, homeout,
                                self.btc_out(bid_tap.scriptPubKey, 1000000 - got)], expiry),
                "Script failed an OP_EQUALVERIFY operation")
        c = self.fee_coin()
        collide("order refund at input 0 (output 0) beside the seller's bid at input 1, which wants output 2",
                self.spend_raw([(REM, rwo), (BID, [bid_leaf, control(bid_tap, "fill")]), (c, None)],
                               [homeout, fee_out, self.btc_out(taker, c[1].nValue.getAmount() - FEE + got),
                                self.btc_out(bid_tap.scriptPubKey, 1000000 - got)], expiry),
                "Script failed an OP_EQUALVERIFY operation")
        self.rec("collision_matrix", matrix)

        # -- 7. home, keyless, with no server ------------------------------------------
        txid = self.force("order remainder home, keyless, server stopped, seller frozen",
                          self.refund_tx([REM], [homeout], order, expiry))
        rt = tx_from_hex(node.getrawtransaction(txid))
        assert bytes(rt.vout[0].scriptPubKey) == enclave["seller"] and rt.vout[0].nValue.getAmount() == ORDER - 100
        self.rec("refund", {"txid": txid, "vsize": node.getrawtransaction(txid, True)["vsize"]})

    def refund_tx(self, coins, outs, tap, locktime, fee_first=False):
        ins_w = [(c, [bytes(tap.leaves["refund"].script), control(tap, "refund")]) for c in coins]
        fc = self.fee_coin()
        ins_w = ([(fc, None)] + ins_w) if fee_first else (ins_w + [(fc, None)])
        btc = b"\x01" + self.BTC
        extra = sum(o.nValue.getAmount() for o in outs if o.nAsset.vchCommitment == btc)
        outs = list(outs) + [self.btc_out(self.spk(), fc[1].nValue.getAmount() - FEE - extra),
                             CTxOut(CTxOutValue(FEE), b"", CTxOutAsset(btc))]
        return self.spend_raw(ins_w, outs, locktime)

    def spend_with(self, ins_w, outs, locktime):
        fc = self.fee_coin()
        outs = list(outs) + [self.btc_out(self.spk(), fc[1].nValue.getAmount() - FEE),
                             CTxOut(CTxOutValue(FEE), b"", CTxOutAsset(b"\x01" + self.BTC))]
        return self.spend_raw(list(ins_w) + [(fc, None)], outs, locktime)

    def spend_raw(self, ins_w, outs, locktime):
        tx = CTransaction()
        tx.nVersion = 2
        tx.nLockTime = locktime
        tx.vin = [CTxIn(c[0], nSequence=NONFINAL) for c, _ in ins_w]
        tx.vout = list(outs)
        tx = sized(tx_from_hex(self.w.signrawtransactionwithwallet(sized(tx).serialize().hex())["hex"]))
        for i, (_, w) in enumerate(ins_w):
            if w is not None:
                tx.wit.vtxinwit[i].scriptWitness.stack = w
        return tx


if __name__ == "__main__":
    tmp = tempfile.mkdtemp(prefix="gated-order-e2e-cfg-")
    cfg = os.path.join(tmp, "config.ini")
    with open(cfg, "w") as f:
        f.write("[environment]\nPACKAGE_NAME=Sequentia Core\nPACKAGE_BUGREPORT=\nSRCDIR={r}\nBUILDDIR={r}\nEXEEXT=\n"
                "RPCAUTH={r}/share/rpcauth/rpcauth.py\n[components]\nENABLE_WALLET=true\nUSE_SQLITE=true\n"
                "USE_BDB=true\nENABLE_CLI=true\nENABLE_WALLET_TOOL=true\nENABLE_BITCOIND=true\n".format(r=REPO))
    os.environ.setdefault("BITCOIND", os.path.join(REPO, "src", "sequentiad"))
    os.environ.setdefault("BITCOINCLI", os.path.join(REPO, "src", "sequentia-cli"))
    sys.argv[1:1] = ["--configfile=" + cfg]
    GatedOrderE2E().main()
