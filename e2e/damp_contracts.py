#!/usr/bin/env python3
"""A network-enforced asset's list of contract templates, set and published
through openampd, and the asset entering an order and leaving it.

    SEQUENTIA_REPO=~/Sequentia OPENAMPD=./openampd/openampd \\
    TOKEN_COVENANTS=~/.local/bin/token-covenants OPENDAMP=~/.local/bin/opendamp \\
    DAMP_REGISTRY=<opendamp>/vectors/addresses.json \\
    OPENDAMP_FILLS=<opendamp>/contracts/seqdex_guarded_order.fills.json \\
    python3 e2e/damp_contracts.py

A Sequentia node on a custom chain (elementsregtest) with Simplicity active
from genesis and -par=1, openampd with the OpenDAMP pinning file and the
token-covenants tool, and the `opendamp` tool. Every document openampd hands
out goes to `opendamp` as it is.

  1. A network-enforced asset is issued to alice, whitelist {alice, bob}. Its
     genesis policy lists no contract template.
  2. POST /v1/issuer/damp-policy with add_contracts [seqdex/guarded-order]:
     openampd prepares seq 1 listing the template, `opendamp derive` agrees on
     pi, the issuer signs, openampd completes, and GET /v1/snapshots serves the
     list. An unknown template is refused before anything is prepared.
  3. Under the published seq 1, alice moves A into her own guarded order
     (`opendamp order-address`, then `opendamp contract-verifier
     --sender-privkey`). Bob takes part of it: the verifier's witness comes from
     `contract-verifier` with no key, and the order's own witness is built here,
     in Python, from the order's terms and its pinned program, with no compiler.
     The A lands in bob's user covenant.
  4. POST /v1/issuer/damp-policy with remove_contracts: seq 2 lists nothing,
     and `contract-verifier` refuses to fill the order under it.

The refusals in blocks are opendamp's `tests/regtest_contracts.rs`; this
proves the service side. EVIDENCE, when set, is a JSON file the results go to.
"""
import hashlib
import http.client
import json
import os
import subprocess
import sys
import tempfile
import time
from decimal import Decimal

REPO = os.environ["SEQUENTIA_REPO"]
sys.path.insert(0, os.path.join(REPO, "test", "functional"))
sys.dont_write_bytecode = True

from test_framework.test_framework import BitcoinTestFramework  # noqa: E402
from test_framework.key import compute_xonly_pubkey, generate_privkey, sign_schnorr  # noqa: E402
from test_framework.messages import COIN  # noqa: E402
from test_framework.address import program_to_witness  # noqa: E402
from test_framework.script import taproot_construct  # noqa: E402

OPENAMPD = os.environ["OPENAMPD"]
TOOL = os.environ["TOKEN_COVENANTS"]
OPENDAMP = os.environ["OPENDAMP"]
DAMP_REGISTRY = os.environ["DAMP_REGISTRY"]
FILLS = os.environ["OPENDAMP_FILLS"]
EVIDENCE = os.environ.get("EVIDENCE", "")
ATOMS = 1_000_000
FEE = 3000
ISSUER_TOKEN = "e2e-issuer-token"
GUARDED = "seqdex/guarded-order"


def ser_compact(n):
    return bytes([n]) if n < 0xfd else b"\xfd" + n.to_bytes(2, "little")


def explicit_out(asset_display, value, spk):
    """An explicit Elements output: asset, value, null nonce, script."""
    return (b"\x01" + bytes.fromhex(asset_display)[::-1] + b"\x01" + value.to_bytes(8, "big") + b"\x00"
            + ser_compact(len(spk)) + spk)


def unsigned_tx(ins, outs, locktime=0):
    """An Elements transaction with no witnesses: version 2, flag 0."""
    b = (2).to_bytes(4, "little") + b"\x00" + ser_compact(len(ins))
    for txid, vout in ins:
        b += bytes.fromhex(txid)[::-1] + vout.to_bytes(4, "little") + b"\x00" + (0xfffffffe).to_bytes(4, "little")
    b += ser_compact(len(outs))
    for o in outs:
        b += o
    return b + locktime.to_bytes(4, "little")


class DampContractsE2E(BitcoinTestFramework):
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
        self.log.info("%s: %s", key, json.dumps(value, default=str)[:700])
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
        data = resp.read()
        conn.close()
        if expect is not None and resp.status != expect:
            raise AssertionError("%s %s -> %d (want %d): %s" % (method, path, resp.status, expect, data.decode()))
        return resp.status, data

    def run(self, argv, ok=True):
        p = subprocess.run(argv, capture_output=True)
        if ok:
            assert p.returncode == 0, "%s: %s" % (argv[:3], p.stderr.decode())
            return p.stdout.decode()
        assert p.returncode != 0, "%s accepted: %s" % (argv[:3], p.stdout.decode()[:300])
        return p.stderr.decode().strip()

    def write(self, name, doc):
        path = os.path.join(self.tmp, name)
        with open(path, "w") as f:
            f.write(doc if isinstance(doc, str) else json.dumps(doc))
        return path

    def derive(self, path, *owners):
        args = [OPENDAMP, "derive", "--snapshot", path]
        for o in owners:
            args += ["--owner", o]
        out = self.run(args)
        lines = dict((l[:15].strip(), l[15:].strip()) for l in out.splitlines() if len(l) > 15)
        shapes = [l.split()[-1] for l in out.splitlines() if l.startswith("P   CMR")]
        cu = {}
        for l in out.splitlines():
            if l.startswith("C_U("):
                cu[l[4:68]] = l.split("(spk ")[1].split(")")[0]
        return lines, shapes, cu

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, 101)
        node.sendtoaddress(address=node.getnewaddress(), amount=1000000, fee_asset_label="bitcoin")
        self.generate(node, 1)
        x = node.issueasset(assetamount=1000000, tokenamount=0, blind=False, fee_asset="bitcoin")["asset"]
        self.generate(node, 1)
        rates = node.getfeeexchangerates()
        rates[x] = 100000000
        node.setfeeexchangerates(rates)
        self.X = x

        tmp = self.tmp = tempfile.mkdtemp(prefix="damp-contracts-", dir=self.options.tmpdir)
        cold = json.loads(self.run([TOOL, "key", "--new", "--key-file", os.path.join(tmp, "cold.key")]))["key"]
        url = __import__("urllib.parse").parse.urlparse(node.url)
        self.amp_port = 19922 + self.options.port_seed % 1000
        log = open(os.path.join(self.options.tmpdir, "openampd.log"), "w")
        proc = subprocess.Popen([
            OPENAMPD, "-listen", "127.0.0.1:%d" % self.amp_port, "-datadir", os.path.join(tmp, "openampd"),
            "-rpc", "http://%s:%d" % (url.hostname, url.port), "-rpcauth", "%s:%s" % (url.username, url.password),
            "-issuertoken", ISSUER_TOKEN, "-feesats", str(FEE),
            "-follow", "200ms", "-tokentool", TOOL, "-capcoldkey", cold, "-dampregistry", DAMP_REGISTRY,
            "-rpcwallet", self.default_wallet_name,
        ], stdout=log, stderr=subprocess.STDOUT)
        try:
            self.with_daemon(node)
        finally:
            proc.terminate()
            proc.wait(timeout=10)

    def p2tr_fee_coin(self, node, sk):
        xonly = compute_xonly_pubkey(sk)[0]
        spk = bytes(taproot_construct(xonly).scriptPubKey)
        txid = node.sendtoaddress(address=program_to_witness(1, spk[2:]), amount=Decimal("0.01"), assetlabel=self.X,
                                  fee_asset_label=self.X)
        self.generate(self.nodes[0], 1)
        d = node.getrawtransaction(txid, True)
        vout = [o["n"] for o in d["vout"] if o["scriptPubKey"]["hex"] == spk.hex()][0]
        return {"txid": txid, "vout": vout, "asset": self.X, "value": 1_000_000, "key": xonly.hex(),
                "privkey": sk.hex(), "amount": FEE, "change_spk": spk.hex()}

    def wallet_coin(self, node, atoms):
        """A wallet coin of X with exactly `atoms`, locked from coin selection."""
        addr = node.getnewaddress("", "bech32")
        txid = node.sendtoaddress(address=addr, amount=Decimal(atoms) / COIN, assetlabel=self.X, fee_asset_label=self.X)
        self.generate(self.nodes[0], 1)
        spk = node.getaddressinfo(addr)["scriptPubKey"]
        d = node.getrawtransaction(txid, True)
        vout = [o["n"] for o in d["vout"] if o["scriptPubKey"]["hex"] == spk][0]
        node.lockunspent(False, [{"txid": txid, "vout": vout}])
        return {"txid": txid, "vout": vout, "value": atoms, "spk": spk}

    def policy_update(self, node, asset, body, sks, cur_label):
        """Both phases of a policy update through openampd and opendamp; returns
        the prepare reply, the derive lines of the next policy and its file."""
        _, raw = self.api("POST", "/v1/issuer/damp-policy", dict(body, asset=asset), token=ISSUER_TOKEN)
        pol = json.loads(raw)
        next_file = self.write("next-%s.json" % cur_label, pol["derive_snapshot"])
        cur_file = self.write("cur-%s.json" % cur_label, pol["derive_current"])
        nlines, nshapes, _ = self.derive(next_file)
        assert nlines["pi"] == pol["pi_next"], (nlines["pi"], pol["pi_next"])
        req = {"sender": "00" * 32, "verifier_outpoint": pol["verifier_outpoint"],
               "fee": self.p2tr_fee_coin(node, generate_privkey())}
        req_file = self.write("update-%s.json" % cur_label, req)
        signed_tx = self.run([OPENDAMP, "issuer-update", "--snapshot", cur_file, "--next-snapshot", next_file,
                              "--request", req_file, "--issuer-privkey", sks["issuer"].hex()]).strip()
        sig = sign_schnorr(sks["issuer"], bytes.fromhex(pol["to_sign"])).hex()
        _, craw = self.api("POST", "/v1/issuer/damp-policy/%s/complete" % pol["policy_id"], {
            "sig": sig, "verifier_cmrs": nshapes, "verifier_spk": nlines["C_V(pi) spk"], "signed_tx": signed_tx,
        }, token=ISSUER_TOKEN)
        comp = json.loads(craw)
        self.generate(self.nodes[0], 1)
        utx = node.getrawtransaction(comp["txid"], True)
        cv = [o["n"] for o in utx["vout"] if o["scriptPubKey"]["hex"] == nlines["C_V(pi) spk"]]
        assert utx["confirmations"] >= 1 and len(cv) == 1
        return pol, comp, nlines, next_file, {"txid": comp["txid"], "vout": cv[0]}

    def with_daemon(self, node):
        node = node.get_wallet_rpc(self.default_wallet_name)
        for _ in range(200):
            try:
                self.api("GET", "/v1/assets")
                break
            except (ConnectionRefusedError, OSError):
                time.sleep(0.1)
        sks = {w: generate_privkey() for w in ("alice", "bob", "issuer")}
        pk = {w: compute_xonly_pubkey(k)[0].hex() for w, k in sks.items()}

        # ---- 1. issuance, no contract listed ------------------------------------
        _, raw = self.api("POST", "/v1/issuer/damp-assets", {
            "name": "Order Bond", "ticker": "ORDB", "precision": 0, "atoms": ATOMS,
            "holder_pubkey": pk["alice"], "whitelist": [pk["alice"], pk["bob"]],
            "issuer_update_key": pk["issuer"], "supply_cap": 0,
        }, token=ISSUER_TOKEN)
        prep = json.loads(raw)
        self.generate(self.nodes[0], 1)
        snap0_file = self.write("snap0.json", prep["derive_snapshot"])
        lines, shapes, _ = self.derive(snap0_file)
        assert lines["contracts"] == "none" and lines["pi"] == prep["pi"]
        _, raw = self.api("POST", "/v1/issuer/damp-assets/%s/complete" % prep["prepare_id"], {
            "user_cmr": lines["U   CMR"], "verifier_cmrs": shapes, "issuer_cmr": lines["G   CMR"],
            "pi": lines["pi"], "verifier_spk": lines["C_V(pi) spk"],
        }, token=ISSUER_TOKEN)
        done = json.loads(raw)
        self.generate(self.nodes[0], 1)
        asset = done["asset"]
        issue_txid = done["txids"]["asset_issue"]
        itx = node.getrawtransaction(issue_txid, True)
        a_out = [o for o in itx["vout"] if o["asset"] == asset][0]
        alice_coin = {"txid": issue_txid, "vout": a_out["n"], "value": int(Decimal(str(a_out["value"])) * COIN)}
        self.rec("issued", {"asset": asset, "txid": issue_txid, "pi0": lines["pi"], "contracts": lines["contracts"]})

        # ---- 2. list the guarded order --------------------------------------------
        code, data = self.api("POST", "/v1/issuer/damp-policy", {
            "asset": asset, "add_contracts": ["seqdex/order"], "reason": "a plain order cannot hold the asset",
        }, token=ISSUER_TOKEN, expect=None)
        assert code == 400, (code, data)
        self.rec("unknown_template_refused", {"status": code, "error": json.loads(data)["error"]})
        pol, comp, nlines, seq1_file, verifier = self.policy_update(
            node, asset, {"add_contracts": [GUARDED], "reason": "holders may rest the asset in SeqDEX orders"},
            sks, "list")
        assert nlines["contracts"].startswith(GUARDED + " "), nlines["contracts"]
        _, latest = self.api("GET", "/v1/snapshots?asset=" + asset)
        latest = json.loads(latest)
        tmpl_hash = nlines["contracts"].split()[1]
        published = latest["snapshot"]
        assert latest["seq"] == 1 and published["predicates"]["contracts"] == [tmpl_hash], published["predicates"]
        assert latest["pi"] == nlines["pi"] == published["pi"]
        self.rec("listed", {"policy_id": pol["policy_id"], "txid": comp["txid"], "seq": latest["seq"],
                            "pi": latest["pi"], "contracts": published["predicates"]["contracts"],
                            "change": pol["change"], "prepare_contracts": pol["contracts"],
                            "derive_line": nlines["contracts"]})

        # ---- 3. into an order, and out of it ---------------------------------------
        lines1, _, cu = self.derive(seq1_file, pk["alice"], pk["bob"])
        cv_spk = lines1["C_V(pi) spk"]
        maker_spk = bytes.fromhex(node.getaddressinfo(node.getnewaddress("", "bech32"))["scriptPubKey"])
        height = node.getblockcount()
        terms = {"asset_b": self.X, "rate_num": 3, "rate_den": 2, "min_lot": 100,
                 "maker": hashlib.sha256(maker_spk).hexdigest(), "expiry": height + 500}
        terms_file = self.write("terms.json", terms)
        order = json.loads(self.run([OPENDAMP, "order-address", "--snapshot", seq1_file, "--owner", pk["alice"],
                                     "--terms", terms_file]))
        order_spk = bytes.fromhex(order["script_pubkey"])
        v_asset = done["verifier_asset"]
        q = done.get("verifier_amount") or json.loads(open(seq1_file).read())["q"]

        def prevout(asset_id, value, spk_hex):
            return {"asset": asset_id, "value": value, "script_pubkey": spk_hex}

        # Entry: [V, C_U(alice), fee coin] -> [V', order, C_U(alice) change, fee change, fee]
        fee1 = self.wallet_coin(node, 50_000)
        put = 600_000
        tx = unsigned_tx(
            [(verifier["txid"], verifier["vout"]), (alice_coin["txid"], alice_coin["vout"]), (fee1["txid"], fee1["vout"])],
            [explicit_out(v_asset, q, bytes.fromhex(cv_spk)), explicit_out(asset, put, order_spk),
             explicit_out(asset, alice_coin["value"] - put, bytes.fromhex(cu[pk["alice"]])),
             explicit_out(self.X, fee1["value"] - FEE, bytes.fromhex(fee1["spk"])),
             explicit_out(self.X, FEE, b"")])
        doc = {"tx": tx.hex(), "sender": pk["alice"],
               "prevouts": [prevout(v_asset, q, cv_spk), prevout(asset, alice_coin["value"], cu[pk["alice"]]),
                            prevout(self.X, fee1["value"], fee1["spk"])],
               "inputs": [{"index": 1, "role": "user"}],
               "outputs": [{"index": 1, "role": "order", "terms": terms}, {"index": 2, "role": "change"}]}
        # The wallet signs its fee coin first; the covenant witnesses go on after,
        # since no signature commits to another input's witness.
        doc["tx"] = node.signrawtransactionwithwallet(doc["tx"])["hex"]
        out = json.loads(self.run([OPENDAMP, "contract-verifier", "--snapshot", seq1_file, "--transaction",
                                   self.write("entry.json", doc), "--sender-privkey", sks["alice"].hex()]))
        signed = {"hex": out["tx"]}
        acc = node.testmempoolaccept([signed["hex"]])[0]
        assert acc["allowed"], acc
        entry_txid = node.sendrawtransaction(signed["hex"])
        self.generate(self.nodes[0], 1)
        etx = node.getrawtransaction(entry_txid, True)
        assert etx["confirmations"] >= 1 and etx["vout"][1]["scriptPubKey"]["hex"] == order["script_pubkey"]
        self.rec("entered", {"txid": entry_txid, "vsize": etx["vsize"], "order_address": order["address"],
                             "atoms_in_the_order": put})

        # Fill: [V, order, payment coin] -> [V', A to C_U(bob), payment to the
        # maker (2), the rest (3), payment change, fee]
        pay = self.wallet_coin(node, 2_000_000)
        filled = 250_001
        price = -(-filled * 3 // 2)
        tx = unsigned_tx(
            [(entry_txid, 0), (entry_txid, 1), (pay["txid"], pay["vout"])],
            [explicit_out(v_asset, q, bytes.fromhex(cv_spk)), explicit_out(asset, filled, bytes.fromhex(cu[pk["bob"]])),
             explicit_out(self.X, price, maker_spk), explicit_out(asset, put - filled, order_spk),
             explicit_out(self.X, pay["value"] - price - FEE, bytes.fromhex(pay["spk"])),
             explicit_out(self.X, FEE, b"")])
        doc = {"tx": tx.hex(), "sender": pk["alice"],
               "prevouts": [prevout(v_asset, q, cv_spk), prevout(asset, put, order["script_pubkey"]),
                            prevout(self.X, pay["value"], pay["spk"])],
               "inputs": [{"index": 1, "role": "order", "terms": terms}],
               "outputs": [{"index": 1, "role": "pay", "owner": pk["bob"]},
                           {"index": 3, "role": "order", "terms": terms}]}
        doc["tx"] = node.signrawtransactionwithwallet(doc["tx"])["hex"]
        fill_doc = self.write("fill.json", doc)
        out = json.loads(self.run([OPENDAMP, "contract-verifier", "--snapshot", seq1_file, "--transaction", fill_doc]))
        # The order's own witness, with no compiler: the data leaf's bytes and
        # PATH Left(true) (0x40), its pinned fill program, its root and control block.
        fills = json.load(open(FILLS))
        assert fills["cmr"] == order["cmr"]
        stack = [bytes.fromhex(order["data"]) + b"\x40", bytes.fromhex(fills["paths"]["fill"]["program"]),
                 bytes.fromhex(order["cmr"]), bytes.fromhex(order["control_block"])]
        signed = {"hex": self.with_witness(out["tx"], 1, stack)}
        acc = node.testmempoolaccept([signed["hex"]])[0]
        assert acc["allowed"], acc
        fill_txid = node.sendrawtransaction(signed["hex"])
        self.generate(self.nodes[0], 1)
        ftx = node.getrawtransaction(fill_txid, True)
        assert ftx["confirmations"] >= 1
        assert ftx["vout"][1]["scriptPubKey"]["hex"] == cu[pk["bob"]], "the A did not reach bob's user covenant"
        assert ftx["vout"][3]["scriptPubKey"]["hex"] == order["script_pubkey"]
        self.rec("filled", {"txid": fill_txid, "vsize": ftx["vsize"], "filled": filled, "paid": price,
                            "to": "C_U(bob)", "rest_in_the_order": put - filled,
                            "order_witness_built_in_python": True})

        # ---- 4. take the template off the list ----------------------------------
        pol2, comp2, nlines2, seq2_file, _ = self.policy_update(
            node, asset, {"remove_contracts": [GUARDED], "reason": "orders closed"}, sks, "delist")
        assert nlines2["contracts"] == "none"
        _, latest = self.api("GET", "/v1/snapshots?asset=" + asset)
        latest = json.loads(latest)
        assert latest["seq"] == 2 and "contracts" not in latest["snapshot"]["predicates"], latest["snapshot"]
        # The rest of the order, filled again under seq 2: the same layout, with
        # the seq-2 verifier at input 0 and the fill's change paying.
        cv2 = nlines2["C_V(pi) spk"]
        change = {"txid": fill_txid, "vout": 4, "value": pay["value"] - price - FEE, "spk": pay["spk"]}
        rest, f2 = put - filled, 100_000
        p2 = -(-f2 * 3 // 2)
        doc = {"tx": unsigned_tx(
                   [(comp2["txid"], 0), (fill_txid, 3), (change["txid"], change["vout"])],
                   [explicit_out(v_asset, q, bytes.fromhex(cv2)), explicit_out(asset, f2, bytes.fromhex(cu[pk["bob"]])),
                    explicit_out(self.X, p2, maker_spk), explicit_out(asset, rest - f2, order_spk),
                    explicit_out(self.X, change["value"] - p2 - FEE, bytes.fromhex(change["spk"])),
                    explicit_out(self.X, FEE, b"")]).hex(),
               "sender": pk["alice"],
               "prevouts": [prevout(v_asset, q, cv2), prevout(asset, rest, order["script_pubkey"]),
                            prevout(self.X, change["value"], change["spk"])],
               "inputs": [{"index": 1, "role": "order", "terms": terms}],
               "outputs": [{"index": 1, "role": "pay", "owner": pk["bob"]},
                           {"index": 3, "role": "order", "terms": terms}]}
        refused = self.run([OPENDAMP, "contract-verifier", "--snapshot", seq2_file, "--transaction",
                            self.write("fill-delisted.json", doc)], ok=False)
        assert "does not list %s" % GUARDED in refused, refused
        self.rec("delisted", {"txid": comp2["txid"], "seq": latest["seq"], "change": pol2["change"],
                              "tool_refuses_a_fill": refused})

    @staticmethod
    def with_witness(tx_hex, index, stack):
        """`tx_hex` with input `index`'s script witness set to `stack`, as the
        node decodes and re-encodes it."""
        from test_framework.messages import CTransaction  # noqa: F401
        from test_framework.messages import tx_from_hex
        tx = tx_from_hex(tx_hex)
        while len(tx.wit.vtxinwit) < len(tx.vin):
            from test_framework.messages import CTxInWitness
            tx.wit.vtxinwit.append(CTxInWitness())
        tx.wit.vtxinwit[index].scriptWitness.stack = stack
        return tx.serialize().hex()


if __name__ == "__main__":
    DampContractsE2E().main()
