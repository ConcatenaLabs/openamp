#!/usr/bin/env python3
"""The swap escrow through a real openampd against a real node.

    SEQUENTIA_REPO=~/Sequentia OPENAMPD=./openampd/openampd \\
    TOKEN_COVENANTS=<sequentia-contracts>/tools/token-covenants/target/release/token-covenants \\
    python3 e2e/swap_escrow.py

The Sequentia side of a restricted asset sold for on-chain BTC. A Sequentia
node on a custom chain with -par=1, so a block refused for a script names the
script's error; every negative case below is forced into a block with
generateblock, not only refused by the mempool. Time is driven with the node's
mock time, and openampd reads it as the chain's median time past.

The seller locks three escrows of one restricted asset (E1, E2, E3, each for
the same buyer behind its own secret) and two fee pots, in one transaction
openampd co-signs as the seller's own move. Then:

  1. the scripts the server derived equal the scripts built here from the
     terms alone, three leaves and the clawback included;
  2. the claim path refuses, in blocks: no policy signature, a wrong secret,
     and a pot claim without the buyer's key;
  3. the attack of review RV34 D1: the buyer gets E1's claim co-signed, and
     withholds it;
  4. at the cut-off (T_seq minus one hour), less five minutes, E3's claim is
     co-signed, broadcast and mined: the buyer has the asset, and the secret is
     out in the pot's plain witness;
  5. five minutes after the cut-off, openampd refuses to co-sign E2's claim, so
     E2's secret never reaches the chain; the keyless refund is still refused
     in a block (bad-txns-nonfinal) because T_seq has not passed;
  6. the issuer freezes the seller, and openampd refuses to co-sign a move of
     the coin the seller kept; then openampd is STOPPED;
  7. after T_seq, with no server and no key, the refunds refuse in blocks to go
     anywhere but home: another holder's enclave, one atom short, home at
     another output's index, a refund that is not input 0, two escrows in one
     transaction, and an escrow and a pot in one transaction;
  8. the collision matrix: no output of a refund can also count for another
     covenant in the same transaction. The seller rests a SeqDEX bid for the
     asset, paying its enclave, and a SeqDEX ask paid to its payout address
     (the attacks of proof review PV4: a taker filled the seller's own orders
     with the seller's own refunds). Every shape is refused in a block;
  9. E1, E2 and E1's pot go home, each in a keyless transaction of its own as
     input 0 paying output 0, mined;
 10. the withheld claim of step 3 is now refused (its input is spent): the
     buyer cannot take the asset after the refund, which is the attack, closed.
"""
import http.client
import json
import os
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse

REPO = os.environ["SEQUENTIA_REPO"]
sys.path.insert(0, os.path.join(REPO, "test", "functional"))
sys.dont_write_bytecode = True

from test_framework.test_framework import BitcoinTestFramework  # noqa: E402
from test_framework.authproxy import JSONRPCException  # noqa: E402
from test_framework.key import compute_xonly_pubkey, generate_privkey, sign_schnorr  # noqa: E402
from test_framework.messages import (  # noqa: E402
    COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, CTxOutAsset, CTxOutValue, CTxOutWitness,
    sha256, tx_from_hex,
)
from test_framework.script import (  # noqa: E402
    CScript, OP_0, OP_1, OP_CHECKLOCKTIMEVERIFY, OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_DROP, OP_DUP,
    OP_EQUAL, OP_EQUALVERIFY, OP_INSPECTOUTPUTASSET, OP_INSPECTOUTPUTSCRIPTPUBKEY,
    OP_INSPECTOUTPUTVALUE, OP_PUSHCURRENTINPUTINDEX, OP_RETURN, OP_SHA256, OP_SIZE, SIGHASH_DEFAULT,
    TaprootSignatureHash, taproot_construct,
)

OPENAMPD = os.environ["OPENAMPD"]
TOOL = os.environ["TOKEN_COVENANTS"]
EVIDENCE = os.environ.get("EVIDENCE", "")
ISSUER_TOKEN = "e2e-issuer-token"
NUMS = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
FEE = 5000
POT = 20000
ESCROW = 300
NONFINAL = 0xfffffffe
HOUR = 3600


def home(version, program, asset, value):
    """The way home: the coin is input 0, and output 0 pays exactly value of
    asset to the program."""
    return [OP_PUSHCURRENTINPUTINDEX, OP_0, OP_EQUALVERIFY,
            OP_PUSHCURRENTINPUTINDEX, OP_DUP, OP_DUP,
            OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_0 if version == 0 else OP_1, OP_EQUALVERIFY, program, OP_EQUALVERIFY,
            OP_INSPECTOUTPUTASSET, OP_1, OP_EQUALVERIFY, asset, OP_EQUALVERIFY,
            OP_INSPECTOUTPUTVALUE, OP_1, OP_EQUALVERIFY, struct.pack("<Q", value), OP_EQUAL]


def escrow_tap(h, buyer_x, policy_x, issuer_x, t_seq, seller_prog, asset, value):
    leaves = [("claim", CScript([OP_SIZE, 32, OP_EQUALVERIFY, OP_SHA256, h, OP_EQUALVERIFY,
                                 buyer_x, OP_CHECKSIGVERIFY, policy_x, OP_CHECKSIG])),
              ("refund", CScript([t_seq, OP_CHECKLOCKTIMEVERIFY, OP_DROP] + home(1, seller_prog, asset, value)))]
    if issuer_x:
        leaves.append(("claw", CScript([issuer_x, OP_CHECKSIGVERIFY, policy_x, OP_CHECKSIG])))
    return taproot_construct(NUMS, leaves)


def pot_tap(h, buyer_x, t_seq, version, prog, asset, value):
    return taproot_construct(NUMS, [
        ("claim", CScript([OP_SIZE, 32, OP_EQUALVERIFY, OP_SHA256, h, OP_EQUALVERIFY, buyer_x, OP_CHECKSIG])),
        ("refund", CScript([t_seq, OP_CHECKLOCKTIMEVERIFY, OP_DROP] + home(version, prog, asset, value))),
    ])


# The SeqDEX covenant order's FILL leaf, ported byte for byte from seqdex
# daemon/pkg/covenant/leaf.go (BuildFillLeaf) by proof review PV4. A fill at
# input k pays the maker at output 2k and puts the remainder at 2k+1.
def _push(d):
    return bytes([len(d)]) + d


def fill_leaf(asset_a, asset_b, num, den, min_lot, maker_prog):
    le8 = lambda n: struct.pack("<Q", n)  # noqa: E731
    credit, rem = bytes([0xcd, 0x76, 0x93]), bytes([0xcd, 0x76, 0x93, 0x8b])
    s = bytes([0xcd, 0xc9, 0x51, 0x88])
    s += rem + bytes([0xd5, 0x9f, 0x63])
    s += rem + bytes([0xce, 0x51, 0x88]) + _push(asset_a) + bytes([0x87, 0x63])
    s += rem + bytes([0xd1, 0xcd, 0xca, 0x7b, 0x88, 0x88])
    s += rem + bytes([0xcf, 0x51, 0x88, 0x76]) + _push(le8(min_lot)) + bytes([0xdf, 0x69])
    s += bytes([0x67]) + _push(le8(0)) + bytes([0x68, 0x67]) + _push(le8(0)) + bytes([0x68])
    s += bytes([0xd8, 0x69, 0x76]) + _push(le8(min_lot)) + bytes([0xdf, 0x69])
    s += _push(le8(num)) + bytes([0xd9, 0x69]) + _push(le8(den - 1)) + bytes([0xd7, 0x69])
    s += _push(le8(den)) + bytes([0xda, 0x69, 0x77])
    s += credit + bytes([0xce, 0x51, 0x88]) + _push(asset_b) + bytes([0x88])
    s += credit + bytes([0xd1, 0x51, 0x88]) + _push(maker_prog) + bytes([0x88])
    s += credit + bytes([0xcf, 0x51, 0x88, 0x7c, 0xdf])
    return s


def control(tap, name):
    leaf = tap.leaves[name]
    return bytes([leaf.version + tap.negflag]) + tap.internal_pubkey + leaf.merklebranch


def sized(tx):
    while len(tx.wit.vtxinwit) < len(tx.vin):
        tx.wit.vtxinwit.append(CTxInWitness())
    while len(tx.wit.vtxoutwit) < len(tx.vout):
        tx.wit.vtxoutwit.append(CTxOutWitness())
    return tx


class SwapEscrowE2E(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[
            "-initialfreecoins=2100000000000000",
            "-anyonecanspendaremine=1",
            "-blindedaddresses=0",
            "-con_default_blinded_addresses=0",
            "-validatepegin=0",
            "-con_parent_chain_signblockscript=51",
            "-con_any_asset_fees=1",
            "-maxtxfee=100.0",
            "-txindex=1",
            "-evbparams=simplicity:-1:::",
            "-par=1",
        ]]
        self.out = {}

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self, split=False):
        self.setup_nodes()

    def rec(self, key, value):
        self.out[key] = value
        self.log.info("%s: %s", key, json.dumps(value, default=str)[:400])
        if EVIDENCE:
            with open(EVIDENCE, "w") as f:
                json.dump(self.out, f, indent=1, default=str)

    def api(self, method, path, body=None, token=None, expect=200):
        conn = http.client.HTTPConnection("127.0.0.1", self.amp_port, timeout=60)
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        conn.request(method, path, json.dumps(body) if body is not None else None, headers)
        resp = conn.getresponse()
        data = resp.read().decode()
        conn.close()
        if expect is not None and resp.status != expect:
            raise AssertionError("%s %s -> %d (want %d): %s" % (method, path, resp.status, expect, data))
        return resp.status, (json.loads(data) if data else None)

    # -- time and blocks -------------------------------------------------------
    def mine(self, n=1):
        for _ in range(n):
            self.now += 60
            self.node.setmocktime(self.now)
            self.generate(self.node, 1)

    def jump_to(self, t):
        """Move the median time past to just after t: eleven blocks at t."""
        self.now = max(self.now, t)
        self.node.setmocktime(self.now)
        for _ in range(12):
            self.generate(self.node, 1)
        mtp = self.node.getblockheader(self.node.getbestblockhash())["mediantime"]
        assert mtp >= t, (mtp, t)
        return mtp

    def force(self, label, tx):
        h = self.node.generateblock(self.miner, [tx.serialize().hex()], invalid_call=False)["hash"]
        tx.rehash()
        assert tx.hash in self.node.getblock(h)["tx"], label
        self.log.info("   MINED in a forced block: %s %s", label, tx.hash)
        return tx.hash

    def refuse(self, label, tx, reason):
        try:
            self.node.generateblock(self.miner, [tx.serialize().hex()], invalid_call=False)
        except JSONRPCException as e:
            msg = e.error["message"]
            assert reason in msg, "%s: refused for the wrong reason: %s" % (label, msg)
            self.log.info("   REFUSED in a block: %s -> %s", label, msg)
            self.out.setdefault("refused_in_blocks", []).append({"case": label, "error": msg})
            return
        raise AssertionError("%s: block ACCEPTED, expected refusal (%s)" % (label, reason))

    # -- coins -------------------------------------------------------------------
    def spk(self):
        a = self.w.getnewaddress("", "bech32")
        return bytes.fromhex(self.w.getaddressinfo(a)["scriptPubKey"])

    def fee_coin(self):
        addr = self.w.getnewaddress("", "bech32")
        txid = self.w.sendtoaddress(address=addr, amount=1, fee_asset_label="bitcoin")
        self.mine()
        tx = tx_from_hex(self.node.getrawtransaction(txid))
        spk = bytes.fromhex(self.w.getaddressinfo(addr)["scriptPubKey"])
        for i, o in enumerate(tx.vout):
            if bytes(o.scriptPubKey) == spk:
                return COutPoint(int(txid, 16), i), o
        raise AssertionError("fee coin not found")

    def fund_order(self, spk, asset_internal, value):
        """A resting order: value of the asset at spk, funded from the wallet."""
        asset_hex = asset_internal[::-1].hex()
        if asset_internal == self.BTC:
            fee_op, fee_txout = self.fee_coin()
            ins = [(fee_op, fee_txout)]
            change = [self.btc_out(self.spk(), fee_txout.nValue.getAmount() - value - FEE)]
        else:
            u = [u for u in self.w.listunspent() if u["asset"] == asset_hex][0]
            fee_op, fee_txout = self.fee_coin()
            ins = [(COutPoint(int(u["txid"], 16), u["vout"]), None), (fee_op, fee_txout)]
            change = [self.btc_out(self.spk(), fee_txout.nValue.getAmount() - FEE)]
            left = int(round(u["amount"] * 100000000)) - value
            if left:
                change.append(CTxOut(CTxOutValue(left), self.spk(), CTxOutAsset(b"\x01" + asset_internal)))
        tx = CTransaction()
        tx.nVersion = 2
        tx.vin = [CTxIn(op, nSequence=NONFINAL) for op, _ in ins]
        tx.vout = [CTxOut(CTxOutValue(value), spk, CTxOutAsset(b"\x01" + asset_internal))] + change + \
            [CTxOut(CTxOutValue(FEE), b"", CTxOutAsset(b"\x01" + self.BTC))]
        tx = sized(tx_from_hex(self.w.signrawtransactionwithwallet(sized(tx).serialize().hex())["hex"]))
        txid = self.node.sendrawtransaction(tx.serialize().hex())
        self.mine()
        return self.coin_at(txid, 0)

    def coin_at(self, txid, vout):
        tx = tx_from_hex(self.node.getrawtransaction(txid))
        return COutPoint(int(txid, 16), vout), tx.vout[vout]

    def asset_out(self, spk, value, asset_internal=None):
        return CTxOut(CTxOutValue(value), spk, CTxOutAsset(b"\x01" + (asset_internal or self.A)))

    def btc_out(self, spk, value):
        return CTxOut(CTxOutValue(value), spk, CTxOutAsset(b"\x01" + self.BTC))

    def sighash(self, tx, spent, i, script):
        return TaprootSignatureHash(tx, spent, SIGHASH_DEFAULT, self.genesis, i, scriptpath=True, script=script)

    def with_fee(self, ins, outs, locktime=0):
        """ins: [(outpoint, txout)] in order; a wallet fee coin goes last, with its
        change and the fee after outs. Returns (tx, spent) with the fee input signed."""
        fee_op, fee_txout = self.fee_coin()
        tx = CTransaction()
        tx.nVersion = 2
        tx.nLockTime = locktime
        for op, _ in ins:
            tx.vin.append(CTxIn(op, nSequence=NONFINAL))
        tx.vin.append(CTxIn(fee_op, nSequence=NONFINAL))
        tx.vout = list(outs)
        # The fee coin also funds whatever of the fee asset the outputs carry
        # (the pots) beyond what the other inputs bring.
        btc = b"\x01" + self.BTC
        btc_in = sum(t.nValue.getAmount() for _, t in ins if t.nAsset.vchCommitment == btc)
        btc_out = sum(o.nValue.getAmount() for o in outs if o.nAsset.vchCommitment == btc)
        tx.vout.append(self.btc_out(self.spk(), fee_txout.nValue.getAmount() - FEE + btc_in - btc_out))
        tx.vout.append(CTxOut(CTxOutValue(FEE), b"", CTxOutAsset(b"\x01" + self.BTC)))
        signed = self.w.signrawtransactionwithwallet(tx.serialize().hex())
        return sized(tx_from_hex(signed["hex"])), [t for _, t in ins] + [fee_txout]

    # -- the test --------------------------------------------------------------
    def run_test(self):
        self.node = self.nodes[0]
        self.now = int(time.time())
        self.node.setmocktime(self.now)
        self.mine(101)
        self.genesis = int(self.node.getblockhash(0), 16)
        self.BTC = bytes.fromhex(self.node.dumpassetlabels()["bitcoin"])[::-1]
        self.node.sendtoaddress(address=self.node.getnewaddress(), amount=1000000, fee_asset_label="bitcoin")
        self.mine()
        x = self.node.issueasset(assetamount=1000000, tokenamount=0, blind=False, fee_asset="bitcoin")["asset"]
        self.mine()
        rates = self.node.getfeeexchangerates()
        rates[x] = 100000000
        self.node.setfeeexchangerates(rates)

        tmp = tempfile.mkdtemp(prefix="swap-escrow-e2e-", dir=self.options.tmpdir)
        p = subprocess.run([TOOL, "key", "--new", "--key-file", os.path.join(tmp, "cold.key")], capture_output=True)
        assert p.returncode == 0, p.stderr
        cold = json.loads(p.stdout)["key"]
        url = urllib.parse.urlparse(self.node.url)
        self.amp_port = 19922 + self.options.port_seed % 1000
        log = open(os.path.join(self.options.tmpdir, "openampd.log"), "w")
        self.proc = subprocess.Popen([
            OPENAMPD, "-listen", "127.0.0.1:%d" % self.amp_port, "-datadir", os.path.join(tmp, "openampd"),
            "-rpc", "http://%s:%d" % (url.hostname, url.port), "-rpcauth", "%s:%s" % (url.username, url.password),
            "-issuertoken", ISSUER_TOKEN, "-demoissuer", "-feeasset", x, "-feesats", str(FEE),
            "-follow", "200ms", "-tokentool", TOOL, "-capcoldkey", cold,
            "-rpcwallet", self.default_wallet_name,
        ], stdout=log, stderr=subprocess.STDOUT)
        self.rec("openampd_pid", self.proc.pid)
        try:
            self.with_daemon()
        finally:
            if self.proc.poll() is None:
                self.proc.terminate()
                self.proc.wait(timeout=10)

    def with_daemon(self):
        node = self.node
        # openampd loads a watch wallet beside the node's own, so wallet calls name it.
        self.w = node.get_wallet_rpc(self.default_wallet_name)
        self.miner = self.w.getnewaddress("", "bech32")
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
            "name": "Swap Bond", "ticker": "SWAPB", "precision": 0, "atoms": 1000, "clawback": True,
            "holder_aid": aids["seller"], "issuer_aid": aids["issuer"], "supply_cap": 1000,
        }, token=ISSUER_TOKEN)
        asset = res["asset"]
        self.mine()
        self.A = bytes.fromhex(asset)[::-1]
        a = self.api("GET", "/v1/assets/" + asset)[1]
        policy_x, issuer_x = bytes.fromhex(a["policy_pub"]), bytes.fromhex(a["issuer_pub"])
        addr = {w: self.api("GET", "/v1/users/%s/address?asset=%s" % (aids[w], asset))[1] for w in ("seller", "buyer", "other")}
        enclave = {w: bytes.fromhex(addr[w]["script_pubkey"]) for w in addr}
        seller_prog = enclave["seller"][2:]
        payout = self.spk()  # the seller's own address for the pots' way home
        self.rec("asset", {"asset": asset, "policy_x": policy_x.hex(), "clawback": True})

        # The seller's enclave coin of 1000.
        scan = node.scantxoutset("start", ["raw(%s)" % addr["seller"]["script_pubkey"]])
        coin = [u for u in scan["unspents"] if u["asset"] == asset][0]
        seller_coin = self.coin_at(coin["txid"], coin["vout"])
        assert seller_coin[1].nValue.getAmount() == 1000

        secrets = {e: sha256(("secret " + e).encode()) for e in ("E1", "E2", "E3")}
        H = {e: sha256(s) for e, s in secrets.items()}
        t_seq = self.now + 3 * HOUR
        cutoff = t_seq - HOUR
        taps = {e: escrow_tap(H[e], x["buyer"], policy_x, issuer_x, t_seq, seller_prog, self.A, ESCROW) for e in H}
        assert payout[0] == 0 and payout[1] == 20, "a P2WPKH payout"
        pots = {e: pot_tap(H[e], x["buyer"], t_seq, 0, payout[2:], self.BTC, POT) for e in ("E1", "E3")}

        # -- the lock -----------------------------------------------------------
        self.log.info("lock: three escrows and two pots, co-signed as the seller's own move")
        outs = [self.asset_out(taps[e].scriptPubKey, ESCROW) for e in ("E1", "E2", "E3")]
        outs.append(self.asset_out(enclave["seller"], 1000 - 3 * ESCROW))
        outs += [self.btc_out(pots[e].scriptPubKey, POT) for e in ("E1", "E3")]
        lock, spent = self.with_fee([seller_coin], outs)
        _, cs = self.api("POST", "/v1/cosign", {
            "tx": lock.serialize().hex(), "asset": asset, "sender_aid": aids["seller"], "inputs": [0],
            "escrow_outputs": [{"output": i, "buyer_aid": aids["buyer"], "hash": H[e].hex(), "t_seq": t_seq}
                               for i, e in enumerate(("E1", "E2", "E3"))],
        })
        entry = cs["sigs"][0]
        assert entry["sighash"] == self.sighash(lock, spent, 0, bytes.fromhex(entry["leaf"])).hex()
        lock.wit.vtxinwit[0].scriptWitness.stack = [bytes.fromhex(entry["policy_sig"]),
                                                    sign_schnorr(keys["seller"], bytes.fromhex(entry["sighash"])),
                                                    bytes.fromhex(entry["leaf"]), bytes.fromhex(entry["control"])]
        lock_txid = node.sendrawtransaction(lock.serialize().hex())
        self.mine()
        lockt = tx_from_hex(node.getrawtransaction(lock_txid))
        E = {e: self.coin_at(lock_txid, i) for i, e in enumerate(("E1", "E2", "E3"))}
        P = {"E1": self.coin_at(lock_txid, 4), "E3": self.coin_at(lock_txid, 5)}
        # 1. the server's escrow is the one built here from the terms alone.
        for i, e in enumerate(("E1", "E2", "E3")):
            assert bytes(lockt.vout[i].scriptPubKey) == bytes(taps[e].scriptPubKey), e
        self.rec("lock", {"txid": lock_txid, "t_seq": t_seq, "cutoff": cutoff,
                          "escrow_spk": bytes(taps["E1"].scriptPubKey).hex(),
                          "leaf_bytes": {n: len(taps["E1"].leaves[n].script) for n in ("claim", "refund", "claw")},
                          "lock_vsize": node.getrawtransaction(lock_txid, True)["vsize"]})

        # -- the seller's resting SeqDEX orders, for the collision matrix ---------
        # A bid: locks 1,000,000 of the fee asset, buys the restricted asset into
        # the seller's enclave at 1,000 fee-asset atoms per atom.
        bid_leaf = fill_leaf(self.BTC, self.A, 1, 1000, 1000, seller_prog)
        order_refund = CScript([t_seq + 10 * HOUR, OP_CHECKLOCKTIMEVERIFY, OP_DROP, x["seller"], OP_CHECKSIG])
        bid_tap = taproot_construct(NUMS, [("fill", CScript(bid_leaf)), ("refund", order_refund)])
        BID = self.fund_order(bid_tap.scriptPubKey, self.BTC, 1000000)
        # An ask: sells an unrestricted asset X for the fee asset, paid to the
        # seller's payout address, the pots' way home.
        xa = self.w.issueasset(assetamount=10, tokenamount=0, blind=False, fee_asset="bitcoin")["asset"]
        self.mine()
        Xi = bytes.fromhex(xa)[::-1]
        ask_leaf = fill_leaf(Xi, self.BTC, 20000, 100000000, 1000, payout[2:])
        ask_tap = taproot_construct(NUMS, [("fill", CScript(ask_leaf)), ("refund", order_refund)])
        ASK = self.fund_order(ask_tap.scriptPubKey, Xi, 1000000000)
        self.rec("seller_resting_orders", {"bid_for_the_asset": "%064x" % BID[0].hash, "ask_X_for_the_fee_asset": "%064x" % ASK[0].hash})

        def claim_tx(e, pot=True, secret=None, policy=True, buyer_pot_sig=True, to=None):
            """The buyer's claim of escrow e, with its pot paying the fee."""
            ins = [E[e]] + ([P[e]] if pot else [])
            tx = CTransaction()
            tx.nVersion = 2
            for op, _ in ins:
                tx.vin.append(CTxIn(op, nSequence=NONFINAL))
            tx.vout = [self.asset_out(to or enclave["buyer"], ESCROW)]
            if pot:
                tx.vout.append(self.btc_out(self.spk(), POT - FEE))
                tx.vout.append(CTxOut(CTxOutValue(FEE), b"", CTxOutAsset(b"\x01" + self.BTC)))
            sized(tx)
            spent = [t for _, t in ins]
            st, body = self.api("POST", "/v1/cosign", {"tx": tx.serialize().hex(), "asset": asset,
                                                       "sender_aid": aids["seller"], "escrow_inputs": [{"input": 0}]},
                                expect=None)
            return tx, spent, st, body

        def finish(tx, spent, e, body, secret=None, policy=True, buyer_pot_sig=True):
            s = secret or secrets[e]
            claim_leaf = taps[e].leaves["claim"].script
            sh = self.sighash(tx, spent, 0, claim_leaf)
            if body:
                assert body["sigs"][0]["sighash"] == sh.hex()
            # Without the policy signature: the buyer's own signature in its place.
            stack = [bytes.fromhex(body["sigs"][0]["policy_sig"]) if policy else sign_schnorr(keys["buyer"], sh)]
            stack += [sign_schnorr(keys["buyer"], sh), s, bytes(claim_leaf), control(taps[e], "claim")]
            tx.wit.vtxinwit[0].scriptWitness.stack = stack
            if len(spent) > 1:
                pl = pots[e].leaves["claim"].script
                psig = [sign_schnorr(keys["buyer"], self.sighash(tx, spent, 1, pl))] if buyer_pot_sig else [b"\x01" * 64]
                tx.wit.vtxinwit[1].scriptWitness.stack = psig + [s, bytes(pl), control(pots[e], "claim")]
            return tx

        # -- 2. the claim path's refusals, in blocks --------------------------------
        self.log.info("claim path: refusals forced into blocks")
        tx, spent, st, body = claim_tx("E3")
        assert st == 200, body
        self.refuse("claim without the policy signature", finish(tx, spent, "E3", body, policy=False),
                    "Invalid Schnorr signature")
        tx, spent, st, body = claim_tx("E3")
        self.refuse("claim with a wrong secret", finish(tx, spent, "E3", body, secret=sha256(b"wrong")),
                    "Script failed an OP_EQUALVERIFY operation")
        tx, spent, st, body = claim_tx("E3")
        self.refuse("pot claim without the buyer's signature", finish(tx, spent, "E3", body, buyer_pot_sig=False),
                    "Invalid Schnorr signature")
        st, body = claim_tx("E3", to=enclave["other"])[2:]
        assert st == 403 and "buyer's enclave" in body["error"], body
        self.rec("server_refusal_claim_to_another_holder", body)

        # -- 3. RV34 D1: the buyer gets E1's claim co-signed, and withholds it -------
        tx, spent, st, body = claim_tx("E1")
        assert st == 200, body
        withheld = finish(tx, spent, "E1", body)
        assert node.testmempoolaccept([withheld.serialize().hex()])[0]["allowed"]
        self.rec("withheld_claim", {"txid": withheld.rehash(), "valid_now": True})

        # -- 4. a claim just before the cut-off lands --------------------------------
        mtp = self.jump_to(cutoff - 300)
        tx, spent, st, body = claim_tx("E3")
        assert st == 200, body
        assert body["cutoff"] == cutoff
        c3 = finish(tx, spent, "E3", body)
        c3_txid = node.sendrawtransaction(c3.serialize().hex())
        self.mine()
        assert node.getrawtransaction(c3_txid, True)["confirmations"] >= 1
        assert secrets["E3"].hex() in node.getrawtransaction(c3_txid), "the secret is in the claim's witness"
        self.rec("claim_before_cutoff", {"mtp": mtp, "cutoff": cutoff, "txid": c3_txid,
                                         "buyer_gets": "%d atoms of the asset, and the pot less the fee: %d" % (ESCROW, POT - FEE),
                                         "secret_revealed_on_chain": True,
                                         "vsize": node.getrawtransaction(c3_txid, True)["vsize"]})

        # -- 5. after the cut-off: no co-sign, and the refund is not yet valid -------
        mtp = self.jump_to(cutoff + 300)
        st, body = claim_tx("E2", pot=False)[2:]
        assert st == 403 and "cut-off" in body["error"], body
        early, sp = self.with_fee([E["E1"]], [self.asset_out(enclave["seller"], ESCROW)], locktime=t_seq)
        early.wit.vtxinwit[0].scriptWitness.stack = [bytes(taps["E1"].leaves["refund"].script), control(taps["E1"], "refund")]
        self.refuse("refund before T_seq", early, "non-final")
        self.rec("after_cutoff", {"mtp": mtp, "cosign": body,
                                  "buyer_keeps": "its bitcoin: E2's secret was never revealed, so the seller cannot claim it"})

        # -- 6. freeze the seller, then stop the policy server -----------------------
        self.api("POST", "/v1/issuer/freeze", {"aid": aids["seller"], "frozen": True}, token=ISSUER_TOKEN)
        # A frozen seller's own coin cannot move: the change it kept in its enclave.
        change = self.coin_at(lock_txid, 3)
        tx, _ = self.with_fee([change], [self.asset_out(enclave["other"], change[1].nValue.getAmount())])
        st, body = self.api("POST", "/v1/cosign", {"tx": tx.serialize().hex(), "asset": asset,
                                                   "sender_aid": aids["seller"], "inputs": [0]}, expect=None)
        assert st == 403 and "frozen" in body["error"], body
        self.rec("frozen_seller_cosign", body)
        self.proc.terminate()
        self.proc.wait(timeout=10)
        self.rec("policy_server", "stopped, the seller frozen")

        # -- 7. after T_seq, refunds go only home ------------------------------------
        mtp = self.jump_to(t_seq + 300)

        def refund_wit(op):
            key = (op.hash, op.n)
            tap = next((taps[e] for e in E if (E[e][0].hash, E[e][0].n) == key), None) or \
                next(pots[e] for e in P if (P[e][0].hash, P[e][0].n) == key)
            return [bytes(tap.leaves["refund"].script), control(tap, "refund")]

        def refund(ins, outs):
            tx, spent = self.with_fee(ins, outs, locktime=t_seq)
            for i, (op, _) in enumerate(ins):
                tx.wit.vtxinwit[i].scriptWitness.stack = refund_wit(op)
            return tx

        def spend(ins_w, outs):
            """ins_w: [(coin, witness)] in order, witness None for a wallet fee
            coin; outs exactly as given (the caller balances them)."""
            tx = CTransaction()
            tx.nVersion = 2
            tx.nLockTime = t_seq
            tx.vin = [CTxIn(c[0], nSequence=NONFINAL) for c, _ in ins_w]
            tx.vout = list(outs)
            sized(tx)
            tx = sized(tx_from_hex(self.w.signrawtransactionwithwallet(tx.serialize().hex())["hex"]))
            for i, (_, w) in enumerate(ins_w):
                if w is not None:
                    tx.wit.vtxinwit[i].scriptWitness.stack = w
            return tx

        home = self.asset_out(enclave["seller"], ESCROW)
        self.refuse("refund to another holder's enclave", refund([E["E1"]], [self.asset_out(enclave["other"], ESCROW)]),
                    "Script failed an OP_EQUALVERIFY operation")
        self.refuse("refund one atom short", refund([E["E1"]], [self.asset_out(enclave["seller"], ESCROW - 1),
                                                                self.asset_out(enclave["other"], 1)]),
                    "Script evaluated without error but finished with a false/empty top stack element")
        self.refuse("refund home at another output's index", refund([E["E1"]], [CTxOut(CTxOutValue(0), CScript([OP_RETURN]), CTxOutAsset(b"\x01" + self.BTC)), home]),
                    "Script failed an OP_EQUALVERIFY operation")
        self.refuse("pot refund to another address", refund([P["E1"]], [self.btc_out(self.spk(), POT)]),
                    "Script failed an OP_EQUALVERIFY operation")
        fee_c = self.fee_coin()
        fee_back = lambda c: self.btc_out(self.spk(), c[1].nValue.getAmount() - FEE)  # noqa: E731
        fee_out = CTxOut(CTxOutValue(FEE), b"", CTxOutAsset(b"\x01" + self.BTC))
        self.refuse("refund at input 1, home at output 1 (a stranger's fee coin at input 0)",
                    spend([(fee_c, None), (E["E1"], refund_wit(E["E1"][0]))], [fee_back(fee_c), home, fee_out]),
                    "Script failed an OP_EQUALVERIFY operation")

        # -- 8. the collision matrix ----------------------------------------------------
        self.log.info("collision matrix: a refund's output never counts for another covenant")
        matrix = []

        def collide(label, tx, reason):
            self.refuse(label, tx, reason)
            matrix.append({"case": label, "refused": reason})
        # Two refunds of one kind or of two kinds: only one input can be input 0.
        collide("two escrow refunds in one transaction (E1 at 0, E2 at 1, each home)",
                refund([E["E1"], E["E2"]], [home, home]), "Script failed an OP_EQUALVERIFY operation")
        collide("an escrow refund and a pot refund in one transaction (E1 at 0, its pot at 1)",
                refund([E["E1"], P["E1"]], [home, self.btc_out(payout, POT)]), "Script failed an OP_EQUALVERIFY operation")
        collide("a pot refund and an escrow refund in one transaction (the pot at 0, E1 at 1)",
                refund([P["E1"], E["E1"]], [self.btc_out(payout, POT), home]), "Script failed an OP_EQUALVERIFY operation")
        # PV4's X1: the seller's bid at input 1 pays the seller at output 2; the
        # escrow at input 2 sends its coin home at output 2. The taker would take
        # 300,000 of the bid's fee asset for nothing.
        filled = ESCROW * 1000
        c = self.fee_coin()
        taker = self.spk()
        x1_outs = [self.btc_out(taker, c[1].nValue.getAmount() - FEE + filled), fee_out, home,
                   self.btc_out(bid_tap.scriptPubKey, 1000000 - filled)]
        collide("X1: an escrow refund at input 2 as the payment of the seller's bid at input 1 (output 2)",
                spend([(c, None), (BID, [bid_leaf, control(bid_tap, "fill")]), (E["E1"], refund_wit(E["E1"][0]))], x1_outs),
                "Script failed an OP_EQUALVERIFY operation")
        # The same, with the escrow where its refund is valid (input 0): the bid
        # at input 1 can only count output 2, which no longer carries the asset.
        c = self.fee_coin()
        collide("an escrow refund at input 0 (output 0) beside the seller's bid at input 1, which wants output 2",
                spend([(E["E1"], refund_wit(E["E1"][0])), (BID, [bid_leaf, control(bid_tap, "fill")]), (c, None)],
                      [home, fee_out, self.btc_out(taker, c[1].nValue.getAmount() - FEE + filled),
                       self.btc_out(bid_tap.scriptPubKey, 1000000 - filled)]),
                "Script failed an OP_EQUALVERIFY operation")
        # PV4's X2: the seller's ask at input 1 is paid at output 2; the pot at
        # input 2 sends its coin home to the same address at output 2.
        sold = 100000000
        c = self.fee_coin()
        x_out = lambda v, spk: CTxOut(CTxOutValue(v), spk, CTxOutAsset(b"\x01" + Xi))  # noqa: E731
        collide("X2: a pot refund at input 2 as the payment of the seller's ask at input 1 (output 2)",
                spend([(c, None), (ASK, [ask_leaf, control(ask_tap, "fill")]), (P["E1"], refund_wit(P["E1"][0]))],
                      [fee_back(c), x_out(sold, taker), self.btc_out(payout, POT), x_out(1000000000 - sold, ask_tap.scriptPubKey), fee_out]),
                "Script failed an OP_EQUALVERIFY operation")
        c = self.fee_coin()
        collide("a pot refund at input 0 (output 0) beside the seller's ask at input 1, which wants output 2",
                spend([(P["E1"], refund_wit(P["E1"][0])), (ASK, [ask_leaf, control(ask_tap, "fill")]), (c, None)],
                      [self.btc_out(payout, POT), x_out(sold, taker), fee_back(c), x_out(1000000000 - sold, ask_tap.scriptPubKey), fee_out]),
                "Script failed an OP_EQUALVERIFY operation")
        self.rec("collision_matrix", matrix)

        # -- 9. everything goes home, with no key and no server, one coin a transaction
        refunds = {}
        for name, coin, out in (("E1", E["E1"], home), ("E2", E["E2"], home), ("E1's pot", P["E1"], self.btc_out(payout, POT))):
            txid = self.force("%s home, keyless, input 0 paying output 0, policy server stopped" % name, refund([coin], [out]))
            refunds[name] = {"txid": txid, "vsize": node.getrawtransaction(txid, True)["vsize"]}
            rt = tx_from_hex(node.getrawtransaction(txid))
            assert bytes(rt.vout[0].scriptPubKey) == bytes(out.scriptPubKey)
        self.rec("refund", {"mtp": mtp, "t_seq": t_seq, "transactions": refunds,
                            "leaf_bytes": {"escrow_refund": len(taps["E1"].leaves["refund"].script),
                                           "pot_refund": len(pots["E1"].leaves["refund"].script)},
                            "seller_gets": "both escrows back in its enclave, still frozen there, and the pot"})
        # The coin is home in the seller's enclave, whose every move needs the
        # policy key: the freeze still binds it.

        # -- 10. the withheld claim can no longer take the asset ----------------------
        try:
            node.sendrawtransaction(withheld.serialize().hex())
            raise AssertionError("the withheld claim was accepted after the refund")
        except JSONRPCException as e:
            assert "missingorspent" in e.error["message"] or "missing-inputs" in e.error["message"], e.error
            self.rec("withheld_claim_after_refund", e.error["message"])


if __name__ == "__main__":
    tmp = tempfile.mkdtemp(prefix="swap-escrow-e2e-cfg-")
    cfg = os.path.join(tmp, "config.ini")
    with open(cfg, "w") as f:
        f.write("[environment]\nPACKAGE_NAME=Sequentia Core\nPACKAGE_BUGREPORT=\nSRCDIR={r}\nBUILDDIR={r}\nEXEEXT=\n"
                "RPCAUTH={r}/share/rpcauth/rpcauth.py\n[components]\nENABLE_WALLET=true\nUSE_SQLITE=true\n"
                "USE_BDB=true\nENABLE_CLI=true\nENABLE_WALLET_TOOL=true\nENABLE_BITCOIND=true\n".format(r=REPO))
    os.environ.setdefault("BITCOIND", os.path.join(REPO, "src", "sequentiad"))
    os.environ.setdefault("BITCOINCLI", os.path.join(REPO, "src", "sequentia-cli"))
    sys.argv[1:1] = ["--configfile=" + cfg]
    SwapEscrowE2E().main()
