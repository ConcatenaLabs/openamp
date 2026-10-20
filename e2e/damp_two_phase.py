#!/usr/bin/env python3
"""The README's two-phase flows for a network-enforced asset, run as written.

    SEQUENTIA_REPO=~/Sequentia OPENAMPD=./openampd/openampd \\
    TOKEN_COVENANTS=~/.local/bin/token-covenants OPENDAMP=~/.local/bin/opendamp \\
    DAMP_REGISTRY=<opendamp>/vectors/addresses.json \\
    python3 e2e/damp_two_phase.py

A Sequentia node on a custom chain (elementsregtest) with Simplicity active
from genesis (-evbparams=simplicity:-1:::) and -par=1, openampd with the
OpenDAMP pinning file and the token-covenants tool, and the `opendamp` tool.
Every document openampd hands out is written to a file byte for byte and
given to `opendamp` as it is; nothing is converted in between.

  1. Issuance: POST /v1/issuer/damp-assets, `opendamp derive --snapshot
     <derive_snapshot>`, POST /v1/issuer/damp-assets/{id}/complete with what
     derive printed. The asset is issued and C_V(pi_0) holds q of V.
  2. Policy update (a freeze): POST /v1/issuer/damp-policy removing bob and
     blacklisting an outpoint, `opendamp derive --snapshot <derive_snapshot>`,
     `opendamp issuer-update --snapshot <derive_current> --next-snapshot
     <derive_snapshot> --request <fee coin> --issuer-privkey <key>`, the issuer
     signs to_sign, POST /v1/issuer/damp-policy/{id}/complete. The verifier
     moves to C_V(pi_1) and GET /v1/snapshots serves seq 1.
  3. Under pi_1, a transfer from alice to carol settles, built by `opendamp
     transfer-finalize` from the published seq-1 document; one to bob, whom
     the update removed, is refused by the tool.

DERIVE_OUT, when set, is a directory the derive documents are copied to (the
opendamp repository keeps them as test fixtures).
"""
import http.client
import json
import os
import shutil
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
EVIDENCE = os.environ.get("EVIDENCE", "")
DERIVE_OUT = os.environ.get("DERIVE_OUT", "")
ATOMS = 1_000_000
FEE = 3000
ISSUER_TOKEN = "e2e-issuer-token"


class DampTwoPhaseE2E(BitcoinTestFramework):
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
        self.log.info("%s: %s", key, json.dumps(value, default=str)[:600])
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

    def api_json(self, *a, **k):
        code, data = self.api(*a, **k)
        return code, json.loads(data)

    def run(self, argv, ok=True):
        p = subprocess.run(argv, capture_output=True)
        if ok:
            assert p.returncode == 0, "%s: %s" % (argv[:3], p.stderr.decode())
            return p.stdout.decode()
        assert p.returncode != 0, "%s accepted: %s" % (argv[:3], p.stdout.decode()[:300])
        return p.stderr.decode().strip()

    def save_raw(self, raw, field, name):
        """The field of an openampd response, written byte for byte as openampd
        serialized it (no parse and re-dump in between)."""
        doc = json.loads(raw)[field]
        # The field's own bytes, cut out of the response rather than parsed
        # and dumped again, so the file is what openampd wrote.
        text = raw.decode()
        key = '"%s":' % field
        start = text.index(key) + len(key)
        depth, i = 0, start
        while True:
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        piece = text[start:i + 1]
        assert json.loads(piece) == doc
        path = os.path.join(self.tmp, name)
        with open(path, "w") as f:
            f.write(piece)
        if DERIVE_OUT:
            shutil.copy(path, os.path.join(DERIVE_OUT, name))
        return path, doc

    def derive(self, path):
        out = self.run([OPENDAMP, "derive", "--snapshot", path])
        lines = dict((l[:15].strip(), l[15:].strip()) for l in out.splitlines() if len(l) > 15)
        shapes = [l.split()[-1] for l in out.splitlines() if l.startswith("P   CMR")]
        return lines, shapes

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

        tmp = self.tmp = tempfile.mkdtemp(prefix="damp-two-phase-", dir=self.options.tmpdir)
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

    def with_daemon(self, node):
        node = node.get_wallet_rpc(self.default_wallet_name)
        for _ in range(200):
            try:
                self.api("GET", "/v1/assets")
                break
            except (ConnectionRefusedError, OSError):
                time.sleep(0.1)
        sks = {w: generate_privkey() for w in ("alice", "bob", "carol", "issuer")}
        pk = {w: compute_xonly_pubkey(k)[0].hex() for w, k in sks.items()}

        # ---- 1. issuance --------------------------------------------------------
        _, raw = self.api("POST", "/v1/issuer/damp-assets", {
            "name": "Two Phase Bond", "ticker": "TWOP", "precision": 0, "atoms": ATOMS,
            "holder_pubkey": pk["alice"], "whitelist": [pk["alice"], pk["bob"], pk["carol"]],
            "issuer_update_key": pk["issuer"], "supply_cap": 0,
        }, token=ISSUER_TOKEN)
        prep = json.loads(raw)
        self.generate(self.nodes[0], 1)
        snap0_file, snap0 = self.save_raw(raw, "derive_snapshot", "openampd-derive-issue.json")
        lines, shapes = self.derive(snap0_file)
        assert lines["pi"] == prep["pi"] == snap0["pi"], (lines["pi"], prep["pi"])
        self.rec("issuance_derive", {"derive_snapshot_keys": sorted(snap0), "network": snap0["network"],
                                     "pi": lines["pi"], "whitelist_root": lines["whitelist root"],
                                     "blacklist_root": lines["blacklist root"], "cv_spk": lines["C_V(pi) spk"]})
        _, done = self.api_json("POST", "/v1/issuer/damp-assets/%s/complete" % prep["prepare_id"], {
            "user_cmr": lines["U   CMR"], "verifier_cmrs": shapes, "issuer_cmr": lines["G   CMR"],
            "pi": lines["pi"], "verifier_spk": lines["C_V(pi) spk"],
        }, token=ISSUER_TOKEN)
        self.generate(self.nodes[0], 1)
        issue_txid = done["txids"]["asset_issue"]
        itx = node.getrawtransaction(issue_txid, True)
        assert itx["confirmations"] >= 1 and itx["vout"][2]["scriptPubKey"]["hex"] == lines["C_V(pi) spk"]
        asset = done["asset"]
        self.rec("issued", {"asset": asset, "txid": issue_txid, "cv_pi0": lines["C_V(pi) spk"]})

        # ---- 2. a policy update, both phases ---------------------------------------
        frozen_outpoint = {"txid": "7c" * 32, "vout": 3}
        _, raw = self.api("POST", "/v1/issuer/damp-policy", {
            "asset": asset, "remove_whitelist": [pk["bob"]], "add_blacklist": [frozen_outpoint],
            "reason": "e2e: freeze bob and one coin",
        }, token=ISSUER_TOKEN)
        pol = json.loads(raw)
        next_file, next_doc = self.save_raw(raw, "derive_snapshot", "openampd-derive-update.json")
        cur_file, cur_doc = self.save_raw(raw, "derive_current", "openampd-derive-current.json")
        assert cur_doc["pi"] == snap0["pi"] and next_doc["pi"] == pol["pi_next"]
        key = self.run([OPENDAMP, "outpoint-key", "--txid", frozen_outpoint["txid"], "--vout", "3"]).strip()
        assert next_doc["predicates"]["blacklist"]["entries"] == [key], next_doc["predicates"]["blacklist"]
        nlines, nshapes = self.derive(next_file)
        assert nlines["pi"] == pol["pi_next"], (nlines["pi"], pol["pi_next"])
        req = {"sender": pk["alice"], "verifier_outpoint": pol["verifier_outpoint"],
               "fee": self.p2tr_fee_coin(node, generate_privkey())}
        req_file = os.path.join(self.tmp, "update-request.json")
        with open(req_file, "w") as f:
            json.dump(req, f)
        signed_tx = self.run([OPENDAMP, "issuer-update", "--snapshot", cur_file, "--next-snapshot", next_file,
                              "--request", req_file, "--issuer-privkey", sks["issuer"].hex()]).strip()
        sig = sign_schnorr(sks["issuer"], bytes.fromhex(pol["to_sign"])).hex()
        _, comp = self.api_json("POST", "/v1/issuer/damp-policy/%s/complete" % pol["policy_id"], {
            "sig": sig, "verifier_cmrs": nshapes, "verifier_spk": nlines["C_V(pi) spk"], "signed_tx": signed_tx,
        }, token=ISSUER_TOKEN)
        self.generate(self.nodes[0], 1)
        utx = node.getrawtransaction(comp["txid"], True)
        cv1 = [o for o in utx["vout"] if o["scriptPubKey"]["hex"] == nlines["C_V(pi) spk"]]
        assert utx["confirmations"] >= 1 and len(cv1) == 1, utx["vout"]
        _, latest = self.api_json("GET", "/v1/snapshots?asset=" + asset)
        assert latest["seq"] == 1 and latest["pi"] == nlines["pi"], latest
        self.rec("policy_updated", {"txid": comp["txid"], "vsize": utx["vsize"], "seq": latest["seq"],
                                    "pi_1": nlines["pi"], "cv_pi1": nlines["C_V(pi) spk"],
                                    "blacklist_entry": key, "derive_current_pi": cur_doc["pi"]})

        # ---- 3. transfers under pi_1 -------------------------------------------------
        a_out = [o for o in itx["vout"] if o["asset"] == asset][0]
        base = {"sender": pk["alice"], "sender_privkey": sks["alice"].hex(),
                "sender_utxos": [{"txid": issue_txid, "vout": a_out["n"],
                                  "value": int(Decimal(str(a_out["value"])) * COIN)}],
                "amount": 1000, "verifier_outpoint": {"txid": comp["txid"], "vout": cv1[0]["n"]}}
        to_bob = dict(base, recipient=pk["bob"], fee=self.p2tr_fee_coin(node, generate_privkey()))
        with open(os.path.join(self.tmp, "to-bob.json"), "w") as f:
            json.dump(to_bob, f)
        refused = self.run([OPENDAMP, "transfer-finalize", "--snapshot", next_file, "--request",
                            os.path.join(self.tmp, "to-bob.json")], ok=False)
        self.rec("transfer_to_removed_holder_refused", refused)
        to_carol = dict(base, recipient=pk["carol"], fee=self.p2tr_fee_coin(node, generate_privkey()))
        with open(os.path.join(self.tmp, "to-carol.json"), "w") as f:
            json.dump(to_carol, f)
        hexed = self.run([OPENDAMP, "transfer-finalize", "--snapshot", next_file, "--request",
                          os.path.join(self.tmp, "to-carol.json")]).strip()
        tr_txid = node.sendrawtransaction(hexed)
        self.generate(self.nodes[0], 1)
        ttx = node.getrawtransaction(tr_txid, True)
        assert ttx["confirmations"] >= 1
        self.rec("transfer_under_pi1", {"txid": tr_txid, "vsize": ttx["vsize"]})


if __name__ == "__main__":
    DampTwoPhaseE2E().main()
