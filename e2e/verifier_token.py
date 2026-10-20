#!/usr/bin/env python3
"""A network-enforced asset's verifier-asset token through a real openampd.

    SEQUENTIA_REPO=~/Sequentia OPENAMPD=./openampd/openampd \\
    TOKEN_COVENANTS=~/.local/bin/token-covenants OPENDAMP=~/.local/bin/opendamp \\
    DAMP_REGISTRY=<opendamp>/vectors/addresses.json \\
    python3 e2e/verifier_token.py

A Sequentia node on a custom chain (elementsregtest) with Simplicity active
from genesis (-evbparams=simplicity:-1:::) and -par=1. openampd runs with the
token-covenants tool and the OpenDAMP CMR pinning file, pays its fees in an
issued asset on the node's fee whitelist, and:

  1. issues a network-enforced asset in its two phases, `opendamp derive`
     between them: the completion moves A's reissuance token into its supply
     cap and V's reissuance token into its covenant, recording C_V(pi_0), in
     the issuance transaction itself, and the wallet holds neither token;
  2. the issuer halts the asset: `opendamp halt` burns V from C_V(pi_0) with
     the token covenant beside it, and `token-covenants verifier-token record`
     signs the record into it;
  3. the issuer resumes: `token-covenants verifier-token build` reissues q of V
     into the recorded C_V(pi_0); the tool refuses to resume into any other
     script;
  4. a transfer of A settles under pi_0 again, built by `opendamp
     transfer-finalize`.

The covenant's own refusals, each forced into a block beside an accepted
control, are sequentia-contracts' harness test v1; this proves the issuance
openampd makes is one those tools resume from.
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
from test_framework.address import program_to_witness  # noqa: E402
from test_framework.script import taproot_construct  # noqa: E402

OPENAMPD = os.environ["OPENAMPD"]
TOOL = os.environ["TOKEN_COVENANTS"]
OPENDAMP = os.environ["OPENDAMP"]
DAMP_REGISTRY = os.environ["DAMP_REGISTRY"]
EVIDENCE = os.environ.get("EVIDENCE", "")
ATOMS = 1_000_000
FEE = 3000
ISSUER_TOKEN = "e2e-issuer-token"


def opendamp_snapshot(doc, genesis):
    """The fields of a derive-ready snapshot document that `opendamp` reads.
    Its reader refuses any other field, the published snapshot's `pi` and the
    lists' `root` among them (it recomputes both), so they are left out."""
    p = doc["predicates"]
    snap = {k: doc[k] for k in ("v", "asset", "verifier_asset", "q", "tree", "issuer_update_key", "seq", "network",
                                "prev_pi") if k in doc}
    snap["genesis"] = genesis
    snap["predicates"] = {"whitelist": {"entries": p["whitelist"]["entries"]}}
    bl = (p.get("blacklist") or {}).get("entries") or []
    if bl:
        snap["predicates"]["blacklist"] = {"entries": bl}
    if p.get("limit") is not None:
        snap["predicates"]["limit"] = p["limit"]
    return snap


class VerifierTokenE2E(BitcoinTestFramework):
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

    def run(self, argv, request=None, ok=True):
        p = subprocess.run(argv, input=(json.dumps(request) if request is not None else "").encode(), capture_output=True)
        if ok:
            assert p.returncode == 0, "%s: %s" % (argv[:3], p.stderr.decode())
            return p.stdout.decode()
        assert p.returncode != 0, "%s accepted: %s" % (argv[:3], p.stdout.decode()[:300])
        return p.stderr.decode().strip()

    def tool(self, *args, request=None, ok=True):
        out = self.run([TOOL, "verifier-token"] + list(args), request=request, ok=ok)
        return json.loads(out) if ok else out

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
        self.rec("fee_asset", {"asset": x, "whitelist": node.getfeeexchangerates()})
        self.X = x

        tmp = self.tmp = tempfile.mkdtemp(prefix="verifier-token-e2e-", dir=self.options.tmpdir)
        cold = json.loads(self.run([TOOL, "key", "--new", "--key-file", os.path.join(tmp, "cold.key")]))["key"]
        url = __import__("urllib.parse").parse.urlparse(node.url)
        self.amp_port = 19822 + self.options.port_seed % 1000
        self.amp_dir = os.path.join(tmp, "openampd")
        log = open(os.path.join(self.options.tmpdir, "openampd.log"), "w")
        proc = subprocess.Popen([
            OPENAMPD, "-listen", "127.0.0.1:%d" % self.amp_port, "-datadir", self.amp_dir,
            "-rpc", "http://%s:%d" % (url.hostname, url.port), "-rpcauth", "%s:%s" % (url.username, url.password),
            "-issuertoken", ISSUER_TOKEN, "-feeasset", x, "-feesats", str(FEE),
            "-follow", "200ms", "-tokentool", TOOL, "-capcoldkey", cold, "-dampregistry", DAMP_REGISTRY,
            "-rpcwallet", self.default_wallet_name,
        ], stdout=log, stderr=subprocess.STDOUT)
        self.rec("openampd_pid", proc.pid)
        try:
            self.with_daemon(node)
        finally:
            proc.terminate()
            proc.wait(timeout=10)

    def p2tr_fee_coin(self, node, sk):
        """A coin of the fee asset at the key-path taproot output of `sk`, which
        opendamp's requests spend with a raw key."""
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
        genesis = node.getblockhash(0)
        alice_sk, bob_sk, issuer_sk = generate_privkey(), generate_privkey(), generate_privkey()
        alice, bob, issuer = (compute_xonly_pubkey(k)[0].hex() for k in (alice_sk, bob_sk, issuer_sk))
        issuer_file = os.path.join(self.tmp, "issuer.key")
        with open(issuer_file, "w") as f:
            f.write(issuer_sk.hex() + "\n")
        os.chmod(issuer_file, 0o600)

        # ---- 1. issuance, in two phases ------------------------------------------
        _, prep = self.api("POST", "/v1/issuer/damp-assets", {
            "name": "Network Bond", "ticker": "NETB", "precision": 0, "atoms": ATOMS,
            "holder_pubkey": alice, "whitelist": [alice, bob], "issuer_update_key": issuer,
            "network": "regtest", "supply_cap": 0,
        }, token=ISSUER_TOKEN)
        self.generate(self.nodes[0], 1)
        asset, v_asset = prep["asset"], prep["verifier_asset"]
        snap = opendamp_snapshot(prep["derive_snapshot"], genesis)
        snap_file = os.path.join(self.tmp, "snapshot-seq0.json")
        with open(snap_file, "w") as f:
            json.dump(snap, f)
        derived = self.run([OPENDAMP, "derive", "--snapshot", snap_file])
        lines = dict((l[:15].strip(), l[15:].strip()) for l in derived.splitlines() if len(l) > 15)
        shape_cmrs = [l.split()[-1] for l in derived.splitlines() if l.startswith("P   CMR")]
        cv_spk = lines["C_V(pi) spk"]
        self.rec("derived", {"pi": lines["pi"], "u_cmr": lines["U   CMR"], "g_cmr": lines["G   CMR"],
                             "verifier_cmrs": shape_cmrs, "cv_spk": cv_spk})
        _, done = self.api("POST", "/v1/issuer/damp-assets/%s/complete" % prep["prepare_id"], {
            "user_cmr": lines["U   CMR"], "verifier_cmrs": shape_cmrs, "issuer_cmr": lines["G   CMR"],
            "pi": lines["pi"], "verifier_spk": cv_spk,
        }, token=ISSUER_TOKEN)
        self.generate(self.nodes[0], 1)
        issue_txid = done["txids"]["asset_issue"]
        itx = node.getrawtransaction(issue_txid, True)
        vt = done["verifier_token"]
        token_out = itx["vout"][3]
        _, rec = self.api("GET", "/v1/assets/" + asset)
        v_token = rec["damp"]["verifier_token"]["token"]
        assert token_out["asset"] == v_token and token_out["scriptPubKey"]["hex"] == vt["script_pubkey"], token_out
        assert token_out["value"] == 1 and "valuecommitment" not in token_out, token_out
        assert itx["vout"][2]["scriptPubKey"]["hex"] == cv_spk and rec["damp"]["verifier_token"]["recorded"] == cv_spk
        a_token = rec["token"]
        wallet = [u for u in node.listunspent(0) if u["asset"] in (v_token, a_token)]
        assert wallet == [], wallet
        _, supply = self.api("GET", "/v1/supply?asset=" + asset)
        assert supply["verifier_token"]["holds_the_whole_token"] is True, supply
        self.rec("issued", {"asset": asset, "verifier_asset": v_asset, "txid": issue_txid,
                            "v_token_output": {"vout": 3, "script_pubkey": token_out["scriptPubKey"]["hex"],
                                               "address": token_out["scriptPubKey"].get("address"),
                                               "value": token_out["value"]},
                            "a_token_output": {"vout": 1, "script_pubkey": itx["vout"][1]["scriptPubKey"]["hex"]},
                            "wallet_coins_of_either_token": len(wallet), "supply": supply})
        inst_file = os.path.join(self.tmp, "verifier-token.json")
        with open(inst_file, "w") as f:
            f.write(json.dumps(rec["damp"]["verifier_token"]["instance"]))

        # ---- 2. the halt, recording C_V(pi_0) ------------------------------------
        succ = self.tool("address", "--instance", inst_file, "--verifier", cv_spk)
        halt_req = {
            "sender": alice,
            "verifier_outpoint": {"txid": issue_txid, "vout": 2},
            "fee": self.p2tr_fee_coin(node, generate_privkey()),
            "verifier_token": {"txid": issue_txid, "vout": 3, "asset": v_token, "value": 100000000,
                               "script_pubkey": vt["script_pubkey"], "recorded": cv_spk,
                               "successor_spk": succ["script_pubkey"]},
        }
        halt_file = os.path.join(self.tmp, "halt.json")
        with open(halt_file, "w") as f:
            json.dump(halt_req, f)
        unrecorded = dict(halt_req)
        del unrecorded["verifier_token"]
        with open(halt_file + ".bare", "w") as f:
            json.dump(unrecorded, f)
        refused = self.run([OPENDAMP, "halt", "--snapshot", snap_file, "--to-spk", "6a", "--request",
                            halt_file + ".bare", "--issuer-privkey", issuer_sk.hex()], ok=False)
        self.rec("opendamp_refuses_a_halt_that_does_not_record", refused)
        doc = json.loads(self.run([OPENDAMP, "halt", "--snapshot", snap_file, "--to-spk", "6a", "--request", halt_file,
                                   "--issuer-privkey", issuer_sk.hex()]))
        signed = self.tool("record", "--instance", inst_file, "--key-file", issuer_file, request=doc)
        halt_txid = node.sendrawtransaction(signed["hex"])
        self.generate(self.nodes[0], 1)
        assert node.gettxout(issue_txid, 2) is None and node.gettxout(halt_txid, 0) is None
        self.rec("halted", {"txid": halt_txid, "recorded": signed["recorded"],
                            "vsize": node.getrawtransaction(halt_txid, True)["vsize"]})

        # ---- 3. the resume --------------------------------------------------------
        assert rec["damp"]["verifier_token"]["entropy"] == self.v_entropy(node, rec), "V's entropy as recorded"
        fee_utxo = [u for u in node.listunspent(1) if u["asset"] == self.X and u["amount"] >= Decimal("0.0001")][0]
        resume = {"path": "resume", "coin": {"tx": node.getrawtransaction(halt_txid), "vout": 1},
                  "verifier": cv_spk, "entropy": rec["damp"]["verifier_token"]["entropy"],
                  "fee": {"coins": [{"tx": node.getrawtransaction(fee_utxo["txid"]), "vout": fee_utxo["vout"]}],
                          "atoms": str(FEE), "change_to": node.getaddressinfo(node.getnewaddress())["scriptPubKey"]}}
        other = node.getaddressinfo(node.getnewaddress())["scriptPubKey"]
        self.rec("tool_refuses_a_resume_into_another_script",
                 self.tool("build", "--instance", inst_file, "--key-file", issuer_file,
                           request=dict(resume, verifier=other), ok=False))
        built = self.tool("build", "--instance", inst_file, "--key-file", issuer_file, request=resume)
        signed = node.signrawtransactionwithwallet(built["hex"])
        assert signed["complete"], signed
        res_txid = node.sendrawtransaction(signed["hex"])
        self.generate(self.nodes[0], 1)
        rtx = node.getrawtransaction(res_txid, True)
        assert rtx["vout"][1]["scriptPubKey"]["hex"] == cv_spk and rtx["vout"][1]["asset"] == v_asset
        assert int(Decimal(str(rtx["vout"][1]["value"])) * COIN) == snap["q"], rtx["vout"][1]
        self.rec("resumed", {"txid": res_txid, "vsize": rtx["vsize"], "verifier_output": rtx["vout"][1]})

        # ---- 4. a transfer settles under pi_0 again --------------------------------
        a_out = [o for o in itx["vout"] if o["asset"] == asset][0]
        transfer = {
            "sender": alice, "sender_privkey": alice_sk.hex(),
            "sender_utxos": [{"txid": issue_txid, "vout": a_out["n"], "value": int(Decimal(str(a_out["value"])) * COIN)}],
            "recipient": bob, "amount": 1000,
            "verifier_outpoint": {"txid": res_txid, "vout": 1},
            "fee": self.p2tr_fee_coin(node, generate_privkey()),
        }
        tr_file = os.path.join(self.tmp, "transfer.json")
        with open(tr_file, "w") as f:
            json.dump(transfer, f)
        hexed = self.run([OPENDAMP, "transfer-finalize", "--snapshot", snap_file, "--request", tr_file]).strip()
        tr_txid = node.sendrawtransaction(hexed)
        self.generate(self.nodes[0], 1)
        assert node.getrawtransaction(tr_txid, True)["confirmations"] >= 1
        self.rec("transfer_after_the_resume", {"txid": tr_txid})

    def v_entropy(self, node, rec):
        """V's issuance entropy, from the transaction that issued V."""
        for i in node.listissuances():
            if i["asset"] == rec["damp"]["verifier_asset"]:
                return i["entropy"]
        raise AssertionError("V's issuance is not in the wallet")


if __name__ == "__main__":
    VerifierTokenE2E().main()
