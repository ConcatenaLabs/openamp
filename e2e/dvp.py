#!/usr/bin/env python3
"""Delivery against payment through a real openampd against a real node.

    SEQUENTIA_REPO=~/Sequentia OPENAMPD=./openampd/openampd \\
    TOKEN_COVENANTS=<sequentia-contracts>/tools/token-covenants/target/release/token-covenants \\
    python3 e2e/dvp.py

A restricted asset traded for another asset in one transaction: the seller's
enclave coin and the buyer's payment coin in, the asset to the buyer's enclave
and the payment to the seller out. Then:

  1. POST /v1/check approves the trade and signs, records and logs nothing;
     a trade to an account without the asset's category is refused there with
     its code, and still nothing is logged; eligibility names the operator's
     page (-onboarding) beside the asset's own;
  2. POST /v1/cosign with "broadcast": true refuses an expiry signature that is
     not the seller's (400), an expiry already past (403 "expired"), and a
     seller signature that is not over the input (409, nothing in the mempool);
  3. with the seller's own signature and a future expiry, openampd completes
     the witness and broadcasts the trade itself; it is mined, and the buyer
     holds the asset and the seller the payment.
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
HTLC_ATOMS = 300
NONFINAL = 0xfffffffe
HOUR = 3600


def pin(version, program, asset, value):
    return [OP_PUSHCURRENTINPUTINDEX, OP_DUP, OP_DUP,
            OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_0 if version == 0 else OP_1, OP_EQUALVERIFY, program, OP_EQUALVERIFY,
            OP_INSPECTOUTPUTASSET, OP_1, OP_EQUALVERIFY, asset, OP_EQUALVERIFY,
            OP_INSPECTOUTPUTVALUE, OP_1, OP_EQUALVERIFY, struct.pack("<Q", value), OP_EQUAL]


def htlc_tap(h, buyer_x, policy_x, issuer_x, t_seq, seller_prog, asset, value):
    leaves = [("claim", CScript([OP_SIZE, 32, OP_EQUALVERIFY, OP_SHA256, h, OP_EQUALVERIFY,
                                 buyer_x, OP_CHECKSIGVERIFY, policy_x, OP_CHECKSIG])),
              ("refund", CScript([t_seq, OP_CHECKLOCKTIMEVERIFY, OP_DROP] + pin(1, seller_prog, asset, value)))]
    if issuer_x:
        leaves.append(("claw", CScript([issuer_x, OP_CHECKSIGVERIFY, policy_x, OP_CHECKSIG])))
    return taproot_construct(NUMS, leaves)


def pot_tap(h, buyer_x, t_seq, version, prog, asset, value):
    return taproot_construct(NUMS, [
        ("claim", CScript([OP_SIZE, 32, OP_EQUALVERIFY, OP_SHA256, h, OP_EQUALVERIFY, buyer_x, OP_CHECKSIG])),
        ("refund", CScript([t_seq, OP_CHECKLOCKTIMEVERIFY, OP_DROP] + pin(version, prog, asset, value))),
    ])


def control(tap, name):
    leaf = tap.leaves[name]
    return bytes([leaf.version + tap.negflag]) + tap.internal_pubkey + leaf.merklebranch


def sized(tx):
    while len(tx.wit.vtxinwit) < len(tx.vin):
        tx.wit.vtxinwit.append(CTxInWitness())
    while len(tx.wit.vtxoutwit) < len(tx.vout):
        tx.wit.vtxoutwit.append(CTxOutWitness())
    return tx



def tagged(tag, msg):
    t = sha256(tag.encode())
    return sha256(t + t + msg)


class DvPE2E(BitcoinTestFramework):

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

        tmp = tempfile.mkdtemp(prefix="dvp-e2e-", dir=self.options.tmpdir)
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
            "-onboarding", "Test Operator|https://operator.example/apply",
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
            "name": "Trade Bond", "ticker": "TRDB", "precision": 0, "atoms": 1000,
            "holder_aid": aids["seller"], "issuer_aid": aids["issuer"], "supply_cap": 1000,
        }, token=ISSUER_TOKEN)
        asset = res["asset"]
        self.mine()
        self.A = bytes.fromhex(asset)[::-1]
        for who in ("seller", "buyer"):
            self.api("POST", "/v1/issuer/categories", {"aid": aids[who], "categories": ["kyc:eu"]}, token=ISSUER_TOKEN)
        self.api("POST", "/v1/issuer/rules", {"asset": asset, "rules": {"allowed_categories": ["kyc:eu"]}}, token=ISSUER_TOKEN)
        addr = {w: self.api("GET", "/v1/users/%s/address?asset=%s" % (aids[w], asset))[1] for w in ("seller", "buyer", "other")}
        enclave = {w: bytes.fromhex(addr[w]["script_pubkey"]) for w in addr}
        scan = node.scantxoutset("start", ["raw(%s)" % addr["seller"]["script_pubkey"]])
        coin = [u for u in scan["unspents"] if u["asset"] == asset][0]
        seller_coin = self.coin_at(coin["txid"], coin["vout"])
        seller_payout = self.spk()
        PRICE = 50000

        def trade(to):
            # The buyer's fee coin pays the price and the fee (with_fee puts it last).
            return self.with_fee([seller_coin], [self.asset_out(enclave[to], 400),
                                                 self.asset_out(enclave["seller"], 600),
                                                 self.btc_out(seller_payout, PRICE)])

        def log_len():
            conn = http.client.HTTPConnection("127.0.0.1", self.amp_port, timeout=30)
            conn.request("GET", "/v1/log")
            n = len(conn.getresponse().read().decode().strip().splitlines())
            conn.close()
            return n

        # 1. the dry run
        tx, spent = trade("buyer")
        req = {"tx": tx.serialize().hex(), "asset": asset, "sender_aid": aids["seller"], "inputs": [0]}
        before = log_len()
        _, ok = self.api("POST", "/v1/check", req)
        assert ok == {"ok": True, "atoms": 400}, ok
        bad, _ = trade("other")
        st, body = self.api("POST", "/v1/check", dict(req, tx=bad.serialize().hex()), expect=None)
        assert st == 403 and "category" in body["error"], body
        assert log_len() == before, "a dry run left a log entry"
        e = self.api("GET", "/v1/eligibility?asset=%s&aid=%s" % (asset, aids["other"]))[1]
        assert e["code"] == "category" and e["operator_onboarding"] == {"name": "Test Operator", "url": "https://operator.example/apply"}, e
        self.rec("check", {"approved": ok, "refused": body, "log_entries_added": 0, "eligibility": e})

        # 2. the broadcast's refusals
        tx.rehash()
        leaf = bytes.fromhex(addr["seller"]["transfer_leaf"])
        sh = self.sighash(tx, spent, 0, leaf)
        user_sig = sign_schnorr(keys["seller"], sh).hex()

        def expiry_sig(key, t):
            return sign_schnorr(key, tagged("openamp-dvp-v1", bytes.fromhex(tx.hash) + struct.pack(">Q", t))).hex()

        # openampd judges time by the later of its clock and the chain's median time.
        mtp = node.getblockheader(node.getbestblockhash())["mediantime"]
        later = max(mtp, int(time.time())) + 3600
        breq = dict(req, broadcast=True, user_sigs={"0": user_sig})
        st, body = self.api("POST", "/v1/cosign", dict(breq, expires_at=later, expiry_sig=expiry_sig(keys["buyer"], later)), expect=None)
        assert st == 400 and "expiry_sig" in body["error"], body
        past = min(mtp, int(time.time())) - 600
        st, body = self.api("POST", "/v1/cosign", dict(breq, expires_at=past, expiry_sig=expiry_sig(keys["seller"], past)), expect=None)
        assert st == 403 and "expired" in body["error"], body
        st, body = self.api("POST", "/v1/cosign", dict(breq, user_sigs={"0": sign_schnorr(keys["buyer"], sh).hex()},
                                                       expires_at=later, expiry_sig=expiry_sig(keys["seller"], later)), expect=None)
        assert st == 409 and "not the sender's signature" in body["error"], body
        assert node.getrawmempool() == [], node.getrawmempool()
        self.rec("broadcast_refusals", "wrong expiry signer 400, expired 403, wrong input signature 409; mempool empty")

        # 3. the trade, completed and broadcast by openampd
        _, body = self.api("POST", "/v1/cosign", dict(breq, expires_at=later, expiry_sig=expiry_sig(keys["seller"], later)))
        assert body["txid"] == tx.hash, body
        self.mine()
        done = node.getrawtransaction(body["txid"], True)
        assert done["confirmations"] >= 1
        assert [str(o["value"]) for o in done["vout"][:3]] == ["0.00000400", "0.00000600", "0.00050000"], done["vout"][:3]
        self.rec("trade", {"txid": body["txid"], "vsize": done["vsize"],
                           "buyer_gets": "400 atoms of the asset", "seller_gets": "%d atoms of the payment" % PRICE})


if __name__ == "__main__":
    tmp = tempfile.mkdtemp(prefix="dvp-e2e-cfg-")
    cfg = os.path.join(tmp, "config.ini")
    with open(cfg, "w") as f:
        f.write("[environment]\nPACKAGE_NAME=Sequentia Core\nPACKAGE_BUGREPORT=\nSRCDIR={r}\nBUILDDIR={r}\nEXEEXT=\n"
                "RPCAUTH={r}/share/rpcauth/rpcauth.py\n[components]\nENABLE_WALLET=true\nUSE_SQLITE=true\n"
                "USE_BDB=true\nENABLE_CLI=true\nENABLE_WALLET_TOOL=true\nENABLE_BITCOIND=true\n".format(r=REPO))
    os.environ.setdefault("BITCOIND", os.path.join(REPO, "src", "sequentiad"))
    os.environ.setdefault("BITCOINCLI", os.path.join(REPO, "src", "sequentia-cli"))
    sys.argv[1:1] = ["--configfile=" + cfg]
    DvPE2E().main()
