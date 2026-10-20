#!/usr/bin/env python3
"""The supply cap through a real openampd against a real node.

    SEQUENTIA_REPO=~/Sequentia OPENAMPD=./openampd/openampd \\
    TOKEN_COVENANTS=~/.local/bin/token-covenants \\
    SEQC=<sequentia-contracts>/target/release/seqc CONTRACTS=<sequentia-contracts> \\
    python3 e2e/supply_cap.py

A Sequentia node on a custom chain (elementsregtest) with Simplicity active
from genesis (-evbparams=simplicity:-1:::) and -par=1, so a block refused for a
script names the script's error. openampd runs with the token-covenants tool,
pays its fees in an issued asset on the node's fee whitelist, and:

  1. issues an asset with a supply cap: the reissuance token goes straight to
     the covenant in the issuance transaction, and the wallet holds none of it;
  2. mints through POST /v1/issuer/reissue twice, the second time exactly the
     room left, so the total minted through the covenant reaches the cap;
  3. between them, a mint of one atom more than the room left is forced into a
     block with generateblock and refused for the covenant's reason, beside a
     control (the same coin minting exactly the room left, built by the tool)
     that the node accepts; openampd itself refuses the over-cap request;
  4. at the cap, openampd refuses another atom, the wallet's own reissueasset
     finds no token, and a spend of the covenant coin the wallet signs alone is
     refused by the mempool and in a block.

seqc and a sequentia-contracts checkout are needed for step 3 only: the
negative reuses the control's pruned program and witness, its signature
re-made over its own sig_all_hash with openampd's operator key (this is a test
chain; the key file is openampd's own, in its data directory).
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
from test_framework.authproxy import JSONRPCException  # noqa: E402
from test_framework.key import compute_xonly_pubkey, generate_privkey, sign_schnorr  # noqa: E402
from test_framework.messages import COIN, tx_from_hex, CTransaction  # noqa: E402

OPENAMPD = os.environ["OPENAMPD"]
TOOL = os.environ["TOKEN_COVENANTS"]
SEQC = os.environ.get("SEQC", "")
CONTRACTS = os.environ.get("CONTRACTS", "")
EVIDENCE = os.environ.get("EVIDENCE", "")
CAP = 1_000_000
FIRST = 400_000
FEE = 3000
ISSUER_TOKEN = "e2e-issuer-token"


def bits_of(b):
    return "".join("{:08b}".format(x) for x in b)


def bit_replace(blob, old, new):
    """Replace the bit pattern of `old` by `new` (same length) inside `blob`."""
    B, o, n = bits_of(blob), bits_of(old), bits_of(new)
    assert B.count(o) == 1, "pattern occurs %d times" % B.count(o)
    B = B.replace(o, n)
    return bytes(int(B[i:i + 8], 2) for i in range(0, len(B), 8))


class SupplyCapE2E(BitcoinTestFramework):
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

    # -- openampd ------------------------------------------------------------
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

    def tool(self, *args, request=None):
        p = subprocess.run([TOOL] + list(args), input=(json.dumps(request) if request is not None else "").encode(),
                           capture_output=True)
        assert p.returncode == 0, p.stderr.decode()
        return json.loads(p.stdout.decode())

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, 101)
        node.sendtoaddress(address=node.getnewaddress(), amount=1000000, fee_asset_label="bitcoin")
        self.generate(node, 1)
        # The fee asset: an issued asset on the node's fee whitelist, so no fee
        # falls back to the policy asset.
        x = node.issueasset(assetamount=1000000, tokenamount=0, blind=False, fee_asset="bitcoin")["asset"]
        self.generate(node, 1)
        rates = node.getfeeexchangerates()
        rates[x] = 100000000
        node.setfeeexchangerates(rates)
        self.rec("fee_asset", {"asset": x, "whitelist": node.getfeeexchangerates()})
        self.X = x

        tmp = tempfile.mkdtemp(prefix="supply-cap-e2e-", dir=self.options.tmpdir)
        cold = self.tool("key", "--new", "--key-file", os.path.join(tmp, "cold.key"))["key"]
        url = __import__("urllib.parse").parse.urlparse(node.url)
        self.amp_port = 19722 + self.options.port_seed % 1000
        self.amp_dir = os.path.join(tmp, "openampd")
        log = open(os.path.join(self.options.tmpdir, "openampd.log"), "w")
        proc = subprocess.Popen([
            OPENAMPD, "-listen", "127.0.0.1:%d" % self.amp_port, "-datadir", self.amp_dir,
            "-rpc", "http://%s:%d" % (url.hostname, url.port), "-rpcauth", "%s:%s" % (url.username, url.password),
            "-issuertoken", ISSUER_TOKEN, "-demoissuer", "-feeasset", x, "-feesats", str(FEE),
            "-follow", "200ms", "-tokentool", TOOL, "-capcoldkey", cold,
            "-rpcwallet", self.default_wallet_name,
        ], stdout=log, stderr=subprocess.STDOUT)
        self.rec("openampd_pid", proc.pid)
        try:
            self.with_daemon(node, cold)
        finally:
            proc.terminate()
            proc.wait(timeout=10)

    def with_daemon(self, node, cold):
        # openampd loads a watch wallet beside the node's own, so every wallet
        # call from here on names the wallet.
        node = node.get_wallet_rpc(self.default_wallet_name)
        for _ in range(200):
            try:
                self.api("GET", "/v1/assets")
                break
            except (ConnectionRefusedError, OSError):
                time.sleep(0.1)
        op_file = os.path.join(self.amp_dir, "cap-operator.key")
        assert oct(os.stat(op_file).st_mode & 0o777) == "0o600"
        op_key = self.tool("key", "--key-file", op_file)["key"]
        self.rec("keys", {"operator_key": op_key, "operator_key_file_mode": "0600", "cold_key": cold})

        keys, aids = {}, {}
        for who in ("alice", "issuer"):
            keys[who] = generate_privkey()
            aids[who] = self.api("POST", "/v1/users", {"pubkeys": [compute_xonly_pubkey(keys[who])[0].hex()]})[1]["aid"]

        self.log.info("issue with a supply cap")
        _, res = self.api("POST", "/v1/issuer/assets", {
            "name": "Capped Bond", "ticker": "CAPB", "precision": 0, "atoms": 500_000,
            "holder_aid": aids["alice"], "issuer_aid": aids["issuer"], "supply_cap": CAP,
        }, token=ISSUER_TOKEN)
        asset, token, issue_txid = res["asset"], res["token"], res["txid"]
        self.generate(self.nodes[0], 1)
        itx = node.getrawtransaction(issue_txid, True)
        cap_view = res["supply_cap"]
        token_out = itx["vout"][1]
        assert token_out["asset"] == token and token_out["scriptPubKey"]["hex"] == cap_view["script_pubkey"], token_out
        assert token_out["value"] == 1 and "valuecommitment" not in token_out
        wallet_tokens = [u for u in node.listunspent(0) if u["asset"] == token]
        assert wallet_tokens == [], wallet_tokens
        self.rec("issued", {"asset": asset, "token": token, "txid": issue_txid,
                            "token_output": {"vout": 1, "script_pubkey": token_out["scriptPubKey"]["hex"],
                                             "address": token_out["scriptPubKey"].get("address"), "value": token_out["value"]},
                            "supply_cap": cap_view, "wallet_coins_of_the_token": len(wallet_tokens)})

        def mint(atoms, rid, expect=200):
            return self.api("POST", "/v1/issuer/reissue", {"asset": asset, "target_aid": aids["alice"], "atoms": atoms,
                                                           "request_id": rid}, token=ISSUER_TOKEN, expect=expect)

        self.log.info("first mint through openampd")
        _, m1 = mint(FIRST, "m1")
        self.generate(self.nodes[0], 1)
        self.rec("mint_1", m1)
        room = CAP - FIRST

        self.log.info("openampd refuses one atom over the room left")
        code, over = mint(room + 1, "over", expect=409)
        self.rec("openampd_refuses_one_atom_over", {"http": code, "body": over})

        self.log.info("the same over-cap mint forced into a block, beside its accepted control")
        self.block_negative(node, asset, op_file, room)

        self.log.info("second mint: exactly the room left")
        _, m2 = mint(room, "m2")
        self.generate(self.nodes[0], 1)
        self.rec("mint_2", m2)
        _, sup = self.api("GET", "/v1/supply?asset=" + asset)
        v = sup["supply_cap"]
        assert v["minted_atoms"] == CAP and v["room_atoms"] == 0 and v["holds_the_whole_token"] is True, v
        onchain = 0
        for t in (m1["reissue_txid"], m2["reissue_txid"]):
            d = node.getrawtransaction(t, True)
            onchain += int(Decimal(str(d["vin"][0]["issuance"]["assetamount"])) * COIN)
        assert onchain == CAP, onchain
        self.rec("at_the_cap", {"supply": sup, "minted_on_chain": onchain, "cap": CAP})

        self.log.info("at the cap: openampd refuses, the wallet alone cannot mint")
        code, body = mint(1, "one-more", expect=409)
        self.rec("openampd_refuses_any_mint_at_the_cap", {"http": code, "body": body})
        try:
            node.reissueasset(asset=asset, assetamount=Decimal(1) / COIN, fee_asset=self.X)
            raise AssertionError("the wallet reissued")
        except JSONRPCException as e:
            self.rec("wallet_reissueasset", "%s (code %s)" % (e.error["message"], e.error["code"]))
        assert [u for u in node.listunspent(0) if u["asset"] == token] == []
        self.wallet_alone(node, asset, token, v)

    def coin_of(self, node, txid, vout):
        return {"tx": node.getrawtransaction(txid), "vout": vout}

    def fee_coin(self, node):
        u = [u for u in node.listunspent(1) if u["asset"] == self.X and u["amount"] >= Decimal("0.0001")][0]
        return u

    def block_negative(self, node, asset, op_file, room):
        """Control: the tool's mint of exactly `room` from the current coin
        (testmempoolaccept true, not broadcast). Negative: the same with one
        atom more, the control's pruned program and witness reused and its
        signature re-made over the negative's sig_all_hash."""
        assert SEQC and CONTRACTS, "SEQC and CONTRACTS are needed for the block negative"
        _, a = self.api("GET", "/v1/assets/" + asset)
        c = a["supply_cap"]
        txid, vout = c["coin"].split(":")
        inst_path = os.path.join(self.options.tmpdir, "instance.json")
        _, rec = self.api("GET", "/v1/assets/" + asset)
        # The instance file, from openampd's own record.
        with open(os.path.join(self.amp_dir, "state.json")) as f:
            state = json.load(f)
        instance = state["assets"][asset]["supply_cap"]["instance"]
        with open(inst_path, "w") as f:
            json.dump(instance, f)
        minted = c["minted_atoms"]
        fee = self.fee_coin(node)
        node.lockunspent(False, [{"txid": fee["txid"], "vout": fee["vout"]}])
        mint_to = node.getaddressinfo(node.getnewaddress())["scriptPubKey"]
        change_to = node.getaddressinfo(node.getnewaddress())["scriptPubKey"]
        entropy = state["assets"][asset]["entropy"]
        req = lambda amount: {
            "path": "mint", "coin": self.coin_of(node, txid, int(vout)), "minted": str(minted), "entropy": entropy,
            "amount": str(amount), "mint_to": mint_to,
            "fee": {"coins": [self.coin_of(node, fee["txid"], fee["vout"])], "atoms": str(FEE), "change_to": change_to}}
        control = self.tool("supply-cap", "build", "--instance", inst_path, "--key-file", op_file, request=req(room))
        csigned = node.signrawtransactionwithwallet(control["hex"])["hex"]
        res = node.testmempoolaccept([csigned])[0]
        assert res["allowed"], res
        # The negative: the control's transaction with one atom more minted.
        ctx = tx_from_hex(csigned)
        neg = CTransaction(ctx)
        neg.vin[0].assetIssuance.nAmount.setToAmount(room + 1)
        neg.vout[1].nValue.setToAmount(room + 1)
        stack = ctx.wit.vtxinwit[0].scriptWitness.stack
        witness, program, cmr, cb = (bytes(x) for x in stack)
        source = subprocess.run([SEQC, "expand", os.path.join(CONTRACTS, "templates", "supply_cap", "supply_cap.simf")],
                                capture_output=True, check=True).stdout.decode()
        utxos = []
        for i in neg.vin:
            prev = tx_from_hex(node.getrawtransaction("%064x" % i.prevout.hash))
            utxos.append(prev.vout[i.prevout.n].serialize().hex())
        sh = lambda t: bytes.fromhex(json.loads(subprocess.run(
            [SEQC, "run"], input=json.dumps({"source": source, "args": {}, "tx": t.serialize().hex(), "utxos": utxos,
                                              "index": 0, "control_block": cb.hex(),
                                              "genesis": node.getblockhash(0)}).encode(),
            capture_output=True, check=True).stdout.decode())["sighash_all"])
        with open(op_file) as f:
            op_secret = bytes.fromhex(f.read().strip())
        # The control's signature, found in its witness by its own sighash.
        old_sig = sign_schnorr(op_secret, sh(ctx))
        assert bits_of(witness).count(bits_of(old_sig)) == 1, "the control's signature is not deterministic here"
        neg_stack = [bit_replace(witness, old_sig, sign_schnorr(op_secret, sh(neg))), program, cmr, cb]
        neg.wit.vtxinwit[1].scriptWitness.stack = []
        signed = tx_from_hex(node.signrawtransactionwithwallet(neg.serialize().hex())["hex"])
        signed.wit.vtxinwit[0].scriptWitness.stack = neg_stack  # the wallet keeps no witness it cannot make
        nsigned = signed.serialize().hex()
        mres = node.testmempoolaccept([nsigned])[0]
        h0 = node.getblockcount()
        try:
            self.nodes[0].generateblock(node.getnewaddress(), [nsigned], invalid_call=False)
            raise AssertionError("the over-cap mint was MINED")
        except JSONRPCException as e:
            block_error = "%s (code %s)" % (e.error["message"], e.error["code"])
        assert node.getblockcount() == h0
        assert "Assertion failed inside jet" in block_error, block_error
        assert not mres["allowed"] and "Assertion failed inside jet" in mres.get("reject-reason", ""), mres
        node.lockunspent(True, [{"txid": fee["txid"], "vout": fee["vout"]}])
        self.rec("block_negative_one_atom_over_the_cap", {
            "coin": c["coin"], "minted": minted, "cap": CAP, "room": room,
            "control": {"amount": room, "txid": control["txid"], "testmempoolaccept": True,
                        "vsize": node.decoderawtransaction(csigned)["vsize"]},
            "negative": {"amount": room + 1, "mempool": mres.get("reject-reason"), "block_error": block_error}})

    def wallet_alone(self, node, asset, token, v):
        """A reissuance from the covenant coin that the wallet signs alone: the
        covenant input carries no Simplicity witness the wallet could make."""
        from test_framework.messages import (CAssetIssuance, COutPoint, CTxIn, CTxOut, CTxOutAsset,
                                             CTxOutNonce, CTxOutValue)
        txid, vout = v["coin"].split(":")
        fee = self.fee_coin(node)
        spk = lambda: bytes.fromhex(node.getaddressinfo(node.getnewaddress())["scriptPubKey"])
        out = lambda amount, script, a: CTxOut(nValue=CTxOutValue(amount), scriptPubKey=script,
                                                nAsset=CTxOutAsset(b"\x01" + bytes.fromhex(a)[::-1]), nNonce=CTxOutNonce())
        tx = CTransaction()
        tx.nVersion = 2
        tx.vin = [CTxIn(COutPoint(int(txid, 16), int(vout))), CTxIn(COutPoint(int(fee["txid"], 16), fee["vout"]))]
        fee_atoms = int(Decimal(str(fee["amount"])) * COIN)
        tx.vout = [out(1, spk(), asset), out(v["token_atoms"], spk(), token),
                   out(fee_atoms - FEE, spk(), self.X), out(FEE, b"", self.X)]
        state = json.load(open(os.path.join(self.amp_dir, "state.json")))
        iss = CAssetIssuance()
        iss.assetBlindingNonce = 1
        iss.assetEntropy = int(state["assets"][asset]["entropy"], 16)
        iss.nAmount = CTxOutValue(1)
        tx.vin[0].assetIssuance = iss
        signed = node.signrawtransactionwithwallet(tx.serialize().hex())
        mres = node.testmempoolaccept([signed["hex"]])[0]
        try:
            self.nodes[0].generateblock(node.getnewaddress(), [signed["hex"]], invalid_call=False)
            raise AssertionError("the wallet's own mint was MINED")
        except JSONRPCException as e:
            block_error = "%s (code %s)" % (e.error["message"], e.error["code"])
        assert not mres["allowed"]
        self.rec("wallet_signs_a_mint_alone", {
            "signrawtransactionwithwallet_complete": signed["complete"],
            "signer_errors": [e.get("error") for e in signed.get("errors", [])][:2],
            "mempool": mres.get("reject-reason"), "block_error": block_error})


if __name__ == "__main__":
    tmp = tempfile.mkdtemp(prefix="supply-cap-e2e-cfg-")
    cfg = os.path.join(tmp, "config.ini")
    with open(cfg, "w") as f:
        f.write("[environment]\nPACKAGE_NAME=Sequentia Core\nSRCDIR={r}\nBUILDDIR={r}\nEXEEXT=\n"
                "RPCAUTH={r}/share/rpcauth/rpcauth.py\n[components]\nENABLE_WALLET=true\nUSE_SQLITE=true\n"
                "USE_BDB=true\nENABLE_CLI=true\nENABLE_WALLET_TOOL=true\nENABLE_BITCOIND=true\n".format(r=REPO))
    os.environ.setdefault("BITCOIND", os.path.join(REPO, "src", "sequentiad"))
    os.environ.setdefault("BITCOINCLI", os.path.join(REPO, "src", "sequentia-cli"))
    sys.argv[1:1] = ["--configfile=" + cfg]
    SupplyCapE2E().main()
