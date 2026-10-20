#!/usr/bin/env python3
"""openampd's fee asset by the wallet rule, through a real openampd and node.

    SEQUENTIA_REPO=~/Sequentia OPENAMPD=./openampd/openampd \\
    TOKEN_COVENANTS=~/.local/bin/token-covenants python3 e2e/fee_asset.py

A Sequentia node on a custom chain (elementsregtest) with Simplicity active
from genesis (-evbparams=simplicity:-1:::) and -par=1. The node's wallet holds
the policy asset and an issued asset X, both on its fee whitelist, X rated at
100 reference units a coin. openampd runs with no -feeasset, and:

  1. issues an asset with a supply cap and mints through the cap: X's largest
     coin covers the most fees, so both transactions pay their fee in X, at
     the node's rate (-feesats 3000 reference-unit atoms = 30 atoms of X);
  2. after the node re-rates X at a millionth of a reference unit a coin, the
     policy asset's largest coin covers the most fees, so the next mint pays
     in it, 3000 atoms: the policy asset pays when the rule picks it, and only
     then;
  3. when the node accepts neither, a mint is refused (503) with a line that
     says so, and nothing is built;
  4. started with -feeasset naming an asset the node does not accept, openampd
     refuses to start and says why; naming X, it starts.
"""
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
from test_framework.key import compute_xonly_pubkey, generate_privkey  # noqa: E402
from test_framework.messages import COIN  # noqa: E402

OPENAMPD = os.environ["OPENAMPD"]
TOOL = os.environ["TOKEN_COVENANTS"]
EVIDENCE = os.environ.get("EVIDENCE", "")
FEE_VALUE = 3000  # -feesats: reference-unit atoms
ISSUER_TOKEN = "e2e-issuer-token"


class FeeAssetE2E(BitcoinTestFramework):
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
        self.procs = []

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
        data = resp.read().decode()
        conn.close()
        if expect is not None and resp.status != expect:
            raise AssertionError("%s %s -> %d (want %d): %s" % (method, path, resp.status, expect, data))
        return resp.status, (json.loads(data) if data else None)

    def tool(self, *args):
        p = subprocess.run([TOOL] + list(args), capture_output=True)
        assert p.returncode == 0, p.stderr.decode()
        return json.loads(p.stdout.decode())

    def openampd_args(self, node, datadir, extra):
        url = __import__("urllib.parse").parse.urlparse(node.url)
        return [OPENAMPD, "-listen", "127.0.0.1:%d" % self.amp_port, "-datadir", datadir,
                "-rpc", "http://%s:%d" % (url.hostname, url.port), "-rpcauth", "%s:%s" % (url.username, url.password),
                "-issuertoken", ISSUER_TOKEN, "-demoissuer", "-feesats", str(FEE_VALUE),
                "-follow", "200ms", "-tokentool", TOOL, "-capcoldkey", self.cold,
                "-rpcwallet", self.default_wallet_name] + extra

    def fee_output(self, node, txid):
        """The transaction's fee output: asset and atoms, as the node decodes it."""
        tx = node.getrawtransaction(txid, True)
        fees = [o for o in tx["vout"] if o["scriptPubKey"]["type"] == "fee"]
        assert len(fees) == 1, tx["vout"]
        return {"txid": txid, "fee_asset": fees[0]["asset"],
                "fee_atoms": int(Decimal(str(fees[0]["value"])) * COIN), "vsize": tx["vsize"],
                "confirmations": tx.get("confirmations", 0)}

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, 101)
        node.sendtoaddress(address=node.getnewaddress(), amount=1000000, fee_asset_label="bitcoin")
        self.generate(node, 1)
        policy = node.dumpassetlabels()["bitcoin"]
        x = node.issueasset(assetamount=1000000, tokenamount=0, blind=False, fee_asset="bitcoin")["asset"]
        y = node.issueasset(assetamount=1000, tokenamount=0, blind=False, fee_asset="bitcoin")["asset"]
        self.generate(node, 1)
        rates = node.getfeeexchangerates()
        rates[x] = 10000000000  # 100 reference units a coin of X
        node.setfeeexchangerates(rates)
        self.X, self.Y, self.policy = x, y, policy
        self.rec("node", {"policy_asset": policy, "X": x, "Y_not_accepted": y,
                          "rates": node.getfeeexchangerates()})

        tmp = tempfile.mkdtemp(prefix="fee-asset-e2e-", dir=self.options.tmpdir)
        self.tmp = tmp
        self.cold = self.tool("key", "--new", "--key-file", os.path.join(tmp, "cold.key"))["key"]
        self.amp_port = 19722 + self.options.port_seed % 1000
        try:
            self.refusals(node)
            self.with_rule(node)
        finally:
            for p in self.procs:
                if p.poll() is None:
                    p.terminate()
                    p.wait(timeout=10)

    def refusals(self, node):
        """-feeasset naming an asset the node does not accept: openampd stops."""
        log_path = os.path.join(self.options.tmpdir, "openampd-refused.log")
        with open(log_path, "w") as log:
            p = subprocess.run(self.openampd_args(node, os.path.join(self.tmp, "refused"), ["-feeasset", self.Y]),
                               stdout=log, stderr=subprocess.STDOUT, timeout=30)
        with open(log_path) as f:
            line = f.read().strip().splitlines()[-1]
        assert p.returncode != 0 and "is not an asset this node accepts for fees" in line, (p.returncode, line)
        self.rec("feeasset_not_accepted_refused_at_start", {"exit_code": p.returncode, "line": line})

    def start(self, node, datadir, extra, name):
        log = open(os.path.join(self.options.tmpdir, name), "w")
        proc = subprocess.Popen(self.openampd_args(node, datadir, extra), stdout=log, stderr=subprocess.STDOUT)
        self.procs.append(proc)
        for _ in range(200):
            try:
                self.api("GET", "/v1/assets")
                return proc
            except (ConnectionRefusedError, OSError):
                assert proc.poll() is None, "openampd exited"
                time.sleep(0.1)
        raise AssertionError("openampd did not start")

    def stop(self, proc):
        proc.terminate()
        proc.wait(timeout=10)

    def with_rule(self, node):
        wnode = node.get_wallet_rpc(self.default_wallet_name)
        proc = self.start(node, os.path.join(self.tmp, "openampd"), [], "openampd.log")
        with open(os.path.join(self.options.tmpdir, "openampd.log")) as f:
            self.rec("started_without_feeasset", [l for l in f.read().splitlines() if "listening" in l])

        keys, aids = {}, {}
        for who in ("alice", "issuer"):
            keys[who] = generate_privkey()
            aids[who] = self.api("POST", "/v1/users", {"pubkeys": [compute_xonly_pubkey(keys[who])[0].hex()]})[1]["aid"]

        # 1. The rule picks X: issuance and a mint pay in X.
        _, res = self.api("POST", "/v1/issuer/assets", {
            "name": "Fee Rule Bond", "ticker": "FRB", "precision": 0, "atoms": 500_000,
            "holder_aid": aids["alice"], "issuer_aid": aids["issuer"], "supply_cap": 1_000_000,
        }, token=ISSUER_TOKEN)
        asset = res["asset"]
        self.generate(self.nodes[0], 1)
        issued = self.fee_output(wnode, res["txid"])
        assert issued["fee_asset"] == self.X and issued["fee_atoms"] == 30 and issued["confirmations"] >= 1, issued
        self.rec("issuance_fee_in_X", issued)

        mint = lambda atoms, rid, expect=200: self.api("POST", "/v1/issuer/reissue", {
            "asset": asset, "target_aid": aids["alice"], "atoms": atoms, "request_id": rid},
            token=ISSUER_TOKEN, expect=expect)
        _, m1 = mint(100_000, "m1")
        self.generate(self.nodes[0], 1)
        f1 = self.fee_output(wnode, m1["reissue_txid"])
        assert f1["fee_asset"] == self.X and f1["fee_atoms"] == 30 and f1["confirmations"] >= 1, f1
        self.rec("mint_fee_in_X", f1)

        largest = {}
        for u in wnode.listunspent(1):
            largest[u["asset"]] = max(largest.get(u["asset"], 0), int(Decimal(str(u["amount"])) * COIN))
        self.rec("wallet_largest_coins", largest)
        # 2. Re-rated: the policy asset's coin is now worth most, and pays.
        rates = node.getfeeexchangerates()
        rates[self.X] = 100  # 1e-6 reference units a coin of X
        node.setfeeexchangerates(rates)
        _, m2 = mint(100_000, "m2")
        self.generate(self.nodes[0], 1)
        f2 = self.fee_output(wnode, m2["reissue_txid"])
        assert f2["fee_asset"] == self.policy and f2["fee_atoms"] == FEE_VALUE and f2["confirmations"] >= 1, f2
        self.rec("rerated_mint_fee_in_policy_asset", {"rates": node.getfeeexchangerates(), "fee": f2})

        # 3. The node accepts neither: refused with a clear line, nothing built.
        saved = node.getfeeexchangerates()
        node.setfeeexchangerates({"11" * 32: 100000000})  # only an asset openampd's wallet never held
        before = node.getrawmempool()
        code, body = mint(1, "m3", expect=503)
        assert "no fee coin" in body["error"], body
        assert node.getrawmempool() == before
        self.rec("no_accepted_fee_coin_refused", {"rates": node.getfeeexchangerates(), "http": code, "body": body})
        node.setfeeexchangerates(saved)
        self.stop(proc)

        # 4. -feeasset naming X: accepted at start, and the fee is paid in X
        # even though the policy asset's coin is now worth more.
        proc = self.start(node, os.path.join(self.tmp, "openampd"), ["-feeasset", self.X], "openampd-x.log")
        _, m4 = mint(100_000, "m4")
        self.generate(self.nodes[0], 1)
        f4 = self.fee_output(wnode, m4["reissue_txid"])
        assert f4["fee_asset"] == self.X and f4["fee_atoms"] == FEE_VALUE * 1000000 and f4["confirmations"] >= 1, f4
        self.rec("feeasset_X_mint_fee_in_X", f4)
        self.stop(proc)


if __name__ == "__main__":
    FeeAssetE2E().main()
