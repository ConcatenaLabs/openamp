#!/usr/bin/env python3
"""GET /v1/eligibility through a real openampd against a real node.

    SEQUENTIA_REPO=~/Sequentia OPENAMPD=./openampd/openampd \\
    TOKEN_COVENANTS=<sequentia-contracts>/tools/token-covenants/target/release/token-covenants \\
    python3 e2e/eligibility.py

A Sequentia node on a custom chain (elementsregtest) with Simplicity active
from genesis, so issuance can put the reissuance token in its supply cap.
openampd issues an asset to alice with a category rule and a holder cap, then:

  1. bob, registered but without the category, is told he is not eligible,
     with the rule's code and reason, and where to ask: first the contract's
     domain, then the page the issuer sets;
  2. a hosted transfer alice -> bob is refused at /complete with the same
     reason the eligibility answer gave, and nothing is broadcast;
  3. the issuer grants bob the category: eligibility says yes, and the same
     transfer now settles and confirms;
  4. with a holder cap of 3 now reached (alice, bob, and the issuer, which
     holds the fee conversion's slice), carol, who holds the category, is
     refused with the code "holder_cap", read from the chain;
  5. an unregistered account is told to register, and a frozen one that it is
     frozen.
"""
import http.client
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.parse

REPO = os.environ["SEQUENTIA_REPO"]
sys.path.insert(0, os.path.join(REPO, "test", "functional"))
sys.dont_write_bytecode = True

from test_framework.test_framework import BitcoinTestFramework  # noqa: E402
from test_framework.key import compute_xonly_pubkey, generate_privkey, sign_schnorr  # noqa: E402

OPENAMPD = os.environ["OPENAMPD"]
TOOL = os.environ["TOKEN_COVENANTS"]
EVIDENCE = os.environ.get("EVIDENCE", "")
ISSUER_TOKEN = "e2e-issuer-token"
FEE = 3000


class EligibilityE2E(BitcoinTestFramework):
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
        data = resp.read().decode()
        conn.close()
        if expect is not None and resp.status != expect:
            raise AssertionError("%s %s -> %d (want %d): %s" % (method, path, resp.status, expect, data))
        return resp.status, (json.loads(data) if data else None)

    def tool(self, *args):
        p = subprocess.run([TOOL] + list(args), capture_output=True)
        assert p.returncode == 0, p.stderr.decode()
        return json.loads(p.stdout.decode())

    def eligibility(self, asset, **params):
        q = urllib.parse.urlencode(dict(asset=asset, **params))
        return self.api("GET", "/v1/eligibility?" + q)[1]

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

        tmp = tempfile.mkdtemp(prefix="eligibility-e2e-", dir=self.options.tmpdir)
        cold = self.tool("key", "--new", "--key-file", os.path.join(tmp, "cold.key"))["key"]
        url = urllib.parse.urlparse(node.url)
        self.amp_port = 19822 + self.options.port_seed % 1000
        log = open(os.path.join(self.options.tmpdir, "openampd.log"), "w")
        proc = subprocess.Popen([
            OPENAMPD, "-listen", "127.0.0.1:%d" % self.amp_port, "-datadir", os.path.join(tmp, "openampd"),
            "-rpc", "http://%s:%d" % (url.hostname, url.port), "-rpcauth", "%s:%s" % (url.username, url.password),
            "-issuertoken", ISSUER_TOKEN, "-demoissuer", "-feeasset", x, "-feesats", str(FEE),
            "-follow", "200ms", "-tokentool", TOOL, "-capcoldkey", cold,
            "-rpcwallet", self.default_wallet_name,
        ], stdout=log, stderr=subprocess.STDOUT)
        self.rec("openampd_pid", proc.pid)
        try:
            self.with_daemon(node)
        finally:
            proc.terminate()
            proc.wait(timeout=10)

    def wait_height(self, h):
        for _ in range(100):
            if self.api("GET", "/v1/supply?asset=" + self.asset)[1]["height"] >= h:
                return
            time.sleep(0.2)
        raise AssertionError("openampd did not follow to height %d" % h)

    def with_daemon(self, node):
        for _ in range(200):
            try:
                self.api("GET", "/v1/assets")
                break
            except (ConnectionRefusedError, OSError):
                time.sleep(0.1)
        keys, aids = {}, {}
        for who in ("alice", "bob", "carol", "dave", "issuer"):
            keys[who] = generate_privkey()
            aids[who] = self.api("POST", "/v1/users", {"pubkeys": [compute_xonly_pubkey(keys[who])[0].hex()]})[1]["aid"]

        _, res = self.api("POST", "/v1/issuer/assets", {
            "name": "Eligible Bond", "ticker": "ELIG", "precision": 0, "atoms": 1000,
            "holder_aid": aids["alice"], "issuer_aid": aids["issuer"], "supply_cap": 1000,
            "entity_domain": "bonds.example",
        }, token=ISSUER_TOKEN)
        self.asset = asset = res["asset"]
        self.generate(self.nodes[0], 1)
        self.wait_height(self.nodes[0].getblockcount())
        for who in ("alice", "carol", "dave"):
            self.api("POST", "/v1/issuer/categories", {"aid": aids[who], "categories": ["kyc:eu"]}, token=ISSUER_TOKEN)
        self.api("POST", "/v1/issuer/rules", {"asset": asset, "rules": {
            "allowed_categories": ["kyc:eu"], "holder_cap": 3}}, token=ISSUER_TOKEN)
        self.rec("issued", {"asset": asset, "aids": aids})

        # 1. bob lacks the category: refused, with the contract's domain as the way forward.
        e = self.eligibility(asset, aid=aids["bob"], atoms=100)
        assert not e["eligible"] and e["code"] == "category", e
        assert e["onboarding"] == {"name": "bonds.example", "url": "https://bonds.example"}, e
        self.rec("bob_without_category", e)
        self.api("POST", "/v1/issuer/onboarding", {"asset": asset, "name": "Eligible Bond Issuer",
                                                    "url": "https://bonds.example/apply"}, token=ISSUER_TOKEN)
        e = self.eligibility(asset, aid=aids["bob"], atoms=100)
        assert e["onboarding"] == {"name": "Eligible Bond Issuer", "url": "https://bonds.example/apply"}, e
        self.rec("bob_with_issuer_page", e)
        assert self.api("GET", "/v1/assets/" + asset)[1]["onboarding"]["url"] == "https://bonds.example/apply"

        # 2. The same refusal from a real co-sign, and nothing broadcast.
        mempool_before = self.nodes[0].getrawmempool()
        status, body = self.transfer(keys["alice"], aids["alice"], aids["bob"], asset, 100, expect=403)
        assert e["reason"] in body["error"], (e["reason"], body)
        assert self.nodes[0].getrawmempool() == mempool_before
        self.rec("cosign_refusal", body)

        # 3. bob is granted the category: eligible, and the transfer settles.
        self.api("POST", "/v1/issuer/categories", {"aid": aids["bob"], "categories": ["kyc:eu"]}, token=ISSUER_TOKEN)
        e = self.eligibility(asset, aid=aids["bob"], atoms=100)
        assert e["eligible"] and "onboarding" not in e, e
        _, body = self.transfer(keys["alice"], aids["alice"], aids["bob"], asset, 100)
        self.generate(self.nodes[0], 1)
        assert self.nodes[0].getrawtransaction(body["txid"], True)["confirmations"] >= 1
        self.wait_height(self.nodes[0].getblockcount())
        self.rec("bob_settled", {"eligibility": e, "txid": body["txid"]})

        # 4. The holder cap, read from the chain: alice, bob and the issuer (which
        #    took the fee conversion's slice) hold, so carol would be a fourth.
        e = self.eligibility(asset, aid=aids["carol"], atoms=1)
        assert not e["eligible"] and e["code"] == "holder_cap", e
        e2 = self.eligibility(asset, aid=aids["bob"], atoms=1)
        assert e2["eligible"], e2
        self.rec("holder_cap", {"carol": e, "bob_again": e2})

        # 5. Unregistered and frozen.
        e = self.eligibility(asset, aid="ab" * 20)
        assert not e["eligible"] and e["code"] == "unregistered", e
        self.api("POST", "/v1/issuer/freeze", {"aid": aids["dave"], "frozen": True}, token=ISSUER_TOKEN)
        e = self.eligibility(asset, aid=aids["dave"])
        assert not e["eligible"] and e["code"] == "frozen", e
        self.rec("unregistered_and_frozen", "ok")

    def transfer(self, key, sender, recipient, asset, atoms, expect=200):
        _, b = self.api("POST", "/v1/transfers", {"asset": asset, "sender_aid": sender, "recipient_aid": recipient,
                                                   "atoms": atoms, "fee_mode": "convert"})
        # A test signs the server's digest; a wallet recomputes it (spec 0.4(3)).
        sigs = {str(t["input"]): sign_schnorr(key, bytes.fromhex(t["sighash"]), aux=b"\x00" * 32).hex()
                for t in b["to_sign"]}
        return self.api("POST", "/v1/transfers/%s/complete" % b["id"], {"sigs": sigs}, expect=expect)


if __name__ == "__main__":
    tmp = tempfile.mkdtemp(prefix="eligibility-e2e-cfg-")
    cfg = os.path.join(tmp, "config.ini")
    with open(cfg, "w") as f:
        f.write("[environment]\nPACKAGE_NAME=Sequentia Core\nPACKAGE_BUGREPORT=\nSRCDIR={r}\nBUILDDIR={r}\nEXEEXT=\n"
                "RPCAUTH={r}/share/rpcauth/rpcauth.py\n[components]\nENABLE_WALLET=true\nUSE_SQLITE=true\n"
                "USE_BDB=true\nENABLE_CLI=true\nENABLE_WALLET_TOOL=true\nENABLE_BITCOIND=true\n".format(r=REPO))
    os.environ.setdefault("BITCOIND", os.path.join(REPO, "src", "sequentiad"))
    os.environ.setdefault("BITCOINCLI", os.path.join(REPO, "src", "sequentia-cli"))
    sys.argv[1:1] = ["--configfile=" + cfg]
    EligibilityE2E().main()
