#!/usr/bin/env python3
"""Golden vectors for the swap escrow and fee pot (openampd/internal/elements/escrow.go),
built independently with the Sequentia node repo's functional test framework:

    PYTHONPATH=$SEQ_REPO/test/functional python3 tools/gen_escrow_vectors.py \\
        > openampd/internal/elements/testdata/escrow_vectors.json
"""

import hashlib
import json
import struct

from test_framework.key import compute_xonly_pubkey
from test_framework.script import (
    CScript, OP_0, OP_1, OP_CHECKLOCKTIMEVERIFY, OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_DROP, OP_DUP,
    OP_EQUAL, OP_EQUALVERIFY, OP_INSPECTOUTPUTASSET, OP_INSPECTOUTPUTSCRIPTPUBKEY,
    OP_INSPECTOUTPUTVALUE, OP_PUSHCURRENTINPUTINDEX, OP_SHA256, OP_SIZE, taproot_construct,
)

NUMS = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")


def det(i, n=32):
    return bytes([i] * n)


def home(version, program, asset, value):
    return [OP_PUSHCURRENTINPUTINDEX, OP_0, OP_EQUALVERIFY,
            OP_PUSHCURRENTINPUTINDEX, OP_DUP, OP_DUP,
            OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_0 if version == 0 else OP_1, OP_EQUALVERIFY, program, OP_EQUALVERIFY,
            OP_INSPECTOUTPUTASSET, OP_1, OP_EQUALVERIFY, asset, OP_EQUALVERIFY,
            OP_INSPECTOUTPUTVALUE, OP_1, OP_EQUALVERIFY, struct.pack("<Q", value), OP_EQUAL]


def control(tap, name):
    leaf = tap.leaves[name]
    return (bytes([leaf.version + tap.negflag]) + tap.internal_pubkey + leaf.merklebranch).hex()


def described(tap, names, extra):
    out = dict(extra)
    out["spk"] = bytes(tap.scriptPubKey).hex()
    for n in names:
        out[n + "_script"] = bytes(tap.leaves[n].script).hex()
        out[n + "_control"] = control(tap, n)
    return out


def main():
    out = {}
    s = det(9)
    h = hashlib.sha256(s).digest()
    buyer = compute_xonly_pubkey(det(4))[0]
    policy = compute_xonly_pubkey(det(2))[0]
    issuer = compute_xonly_pubkey(det(3))[0]
    seller_prog = compute_xonly_pubkey(det(5))[0]
    asset = bytes(range(32))  # asymmetric, so a byte-order slip shows
    for name, t_seq, value, claw in (("escrow_claw", 1_794_423_273, 1_000_000, True),
                                     ("escrow_noclaw", 2_000_000_000, 128, False)):
        claim = CScript([OP_SIZE, 32, OP_EQUALVERIFY, OP_SHA256, h, OP_EQUALVERIFY,
                         buyer, OP_CHECKSIGVERIFY, policy, OP_CHECKSIG])
        refund = CScript([t_seq, OP_CHECKLOCKTIMEVERIFY, OP_DROP] + home(1, seller_prog, asset, value))
        leaves = [("claim", claim), ("refund", refund)]
        names = ["claim", "refund"]
        if claw:
            leaves.append(("claw", CScript([issuer, OP_CHECKSIGVERIFY, policy, OP_CHECKSIG])))
            names.append("claw")
        tap = taproot_construct(NUMS, leaves)
        out[name] = described(tap, names, {
            "hash": h.hex(), "buyer_x": buyer.hex(), "policy_x": policy.hex(),
            "issuer_x": issuer.hex() if claw else "", "t_seq": t_seq,
            "seller_program": seller_prog.hex(), "asset": asset.hex(), "value": value})
    for name, version, prog in (("pot_v0", 0, det(6, 20)), ("pot_v1", 1, det(7))):
        claim = CScript([OP_SIZE, 32, OP_EQUALVERIFY, OP_SHA256, h, OP_EQUALVERIFY, buyer, OP_CHECKSIG])
        refund = CScript([1_794_423_273, OP_CHECKLOCKTIMEVERIFY, OP_DROP] + home(version, prog, bytes(range(32, 64)), 5000))
        tap = taproot_construct(NUMS, [("claim", claim), ("refund", refund)])
        out[name] = described(tap, ["claim", "refund"], {
            "hash": h.hex(), "buyer_x": buyer.hex(), "t_seq": 1_794_423_273,
            "seller_version": version, "seller_program": prog.hex(), "fee_asset": bytes(range(32, 64)).hex(), "value": 5000})
    print(json.dumps(out, indent=1, sort_keys=True))


if __name__ == "__main__":
    main()
