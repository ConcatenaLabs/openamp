//! Signing a transfer somebody else laid out.
//!
//! A settlement of a Pignus repurchase spends the OpenDAMP verifier and the
//! lender's C_U in a transaction the other covenant dictates the shape of.
//! `cosign_transfer` owes that transaction the same two witnesses the sender
//! owes their own transfer, and nothing else. These run every covenant on the
//! BitMachine, so a witness that passes here is one a node accepts.

use std::str::FromStr;

use opendamp::elements::secp256k1_zkp::{Keypair, Secp256k1, XOnlyPublicKey};
use opendamp::elements::{
    confidential, AssetId, BlockHash, LockTime, OutPoint, Script, Sequence, Transaction, TxIn,
    TxInWitness, TxOut, Txid,
};
use opendamp::net::Net;
use opendamp::programs::{AssetParams, Shape};
use opendamp::txbuild::{
    build_transfer, complete_transfer, cosign_transfer, regulated_flows, Ctx, Flow, TransferReq,
};

fn key(byte: u8) -> ([u8; 32], XOnlyPublicKey) {
    let mut sk = [byte; 32];
    sk[31] = byte.wrapping_add(1);
    let secp = Secp256k1::new();
    let kp = Keypair::from_seckey_slice(&secp, &sk).expect("valid key");
    (sk, kp.x_only_public_key().0)
}

fn asset(byte: u8) -> AssetId {
    AssetId::from_slice(&[byte; 32]).unwrap()
}

fn outpoint(byte: u8, vout: u32) -> OutPoint {
    OutPoint::new(Txid::from_str(&format!("{:064x}", byte as u128)).unwrap(), vout)
}

const A: u8 = 0xaa;
const V: u8 = 0xbb;
const Q: u64 = 1000;

fn test_ctx(wl: &[XOnlyPublicKey]) -> Ctx {
    let (_, issuer) = key(9);
    let params = AssetParams { asset_a: asset(A), asset_v: asset(V), q: Q };
    let net = Net::regtest(BlockHash::from_str(&format!("{:064x}", 7u8)).unwrap());
    Ctx::new(net, params, issuer, wl, &[]).expect("programs compile")
}

fn transfer_req(sender: XOnlyPublicKey, recipient: XOnlyPublicKey) -> TransferReq {
    let (_, fee_key) = key(3);
    TransferReq {
        sender,
        sender_utxos: vec![(outpoint(0x11, 1), 50_000)],
        recipient,
        amount: 20_000,
        verifier_outpoint: outpoint(0x22, 0),
        fee_utxo: (outpoint(0x33, 0), asset(0xcc), 10_000),
        fee_key,
        fee_amount: 400,
        fee_change_spk: Script::from(vec![0x51]),
        locktime: 0,
        recipient_spk_override: None,
    }
}

fn txin(op: OutPoint) -> TxIn {
    TxIn {
        previous_output: op,
        is_pegin: false,
        script_sig: Script::new(),
        sequence: Sequence::from_consensus(0xffff_ffff),
        asset_issuance: Default::default(),
        witness: TxInWitness::default(),
    }
}

fn out(asset_byte: u8, value: u64, spk: Script) -> TxOut {
    TxOut {
        asset: confidential::Asset::Explicit(asset(asset_byte)),
        value: confidential::Value::Explicit(value),
        nonce: confidential::Nonce::Null,
        script_pubkey: spk,
        witness: Default::default(),
    }
}

fn stack_len(tx: &Transaction, idx: usize) -> usize {
    tx.input[idx].witness.script_witness.len()
}

/// Given the builder's own transfer as a foreign transaction, the cosigner
/// produces witnesses the covenants accept, and the same ones the one-call
/// path does.
#[test]
fn cosigns_the_builders_own_transfer() {
    let (alice_sk, alice) = key(1);
    let (_, bob) = key(2);
    let (fee_sk, _) = key(3);
    let ctx = test_ctx(&[alice, bob]);
    let req = transfer_req(alice, bob);
    let built = build_transfer(&ctx, &req).expect("builds");

    let (tx, report) = cosign_transfer(&ctx, &built.tx, &built.prevouts, &alice_sk, &[bob], true)
        .expect("cosigns and validates");
    assert_eq!(report.shape, built.shape);
    assert_eq!(stack_len(&tx, 0), 4, "the verifier witness is on input 0");
    for idx in &built.user_inputs {
        assert_eq!(stack_len(&tx, *idx), 4, "the user witness is on input {idx}");
    }
    assert_eq!(stack_len(&tx, built.fee_input), 0, "the fee input is not this key's to sign");

    let (full, full_report) =
        complete_transfer(&ctx, &req, &alice_sk, &fee_sk, true).expect("one-call path");
    assert_eq!(report.verifier_witness, full_report.verifier_witness);
    assert_eq!(report.verifier_cost, full_report.verifier_cost);
    assert_eq!(report.user_witnesses, full_report.user_witnesses);
    // The verifier witness carries no signature, so it is byte-for-byte the same.
    assert_eq!(
        tx.input[0].witness.script_witness, full.input[0].witness.script_witness,
        "the verifier witness does not depend on who assembled the transaction"
    );
}

/// The settlement shape: four inputs the other covenant orders, six outputs,
/// the regulated asset moving from C_U(alice) at input 2 to C_U(bob) at output
/// 2, everything else in other assets. Every witness already on the
/// transaction survives.
#[test]
fn cosigns_a_settlement_shaped_transaction() {
    let (alice_sk, alice) = key(1);
    let (_, bob) = key(2);
    let ctx = test_ctx(&[alice, bob]);
    let cv = ctx.cv_info().script_pubkey.clone();
    let cu_alice = ctx.cu_info(&alice).script_pubkey.clone();
    let cu_bob = ctx.cu_info(&bob).script_pubkey.clone();
    let vault = Script::from(vec![0x51, 0x20, 0x77]);
    let lender = Script::from(vec![0x00, 0x14, 0x11]);
    let borrower = Script::from(vec![0x00, 0x14, 0x22]);
    const D: u8 = 0xdd;
    let prevouts = vec![
        out(V, Q, cv.clone()),            // 0 the verifier
        out(D, 5_000, vault),             // 1 the bond vault, another covenant's
        out(A, 20_000, cu_alice.clone()), // 2 C_U(lender)
        out(D, 30_000, borrower.clone()), // 3 the borrower's payment
    ];
    let mut tx = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: (0..4).map(|i| txin(outpoint(0x40 + i as u8, i as u32))).collect(),
        output: vec![
            out(V, Q, cv),                    // 0 the verifier, recreated
            out(D, 25_000, lender.clone()),   // 1 the debt
            out(A, 20_000, cu_bob),           // 2 the asset home
            out(D, 5_000, lender),            // 3 the bond released
            out(D, 4_500, borrower),          // 4 the borrower's change
            out(D, 500, Script::new()),       // 5 the fee
        ],
    };
    // The borrower signed first; their witness must come back untouched.
    tx.input[3].witness.script_witness = vec![vec![0xab; 64]];

    let (signed, report) = cosign_transfer(&ctx, &tx, &prevouts, &alice_sk, &[bob], true)
        .expect("a settlement is a transfer the covenants accept");
    assert_eq!(report.shape, Shape::new(3, 5), "four by six is the p4x6 leaf");
    assert_eq!(stack_len(&signed, 0), 4);
    assert_eq!(stack_len(&signed, 2), 4);
    assert_eq!(stack_len(&signed, 1), 0, "the vault is the other covenant's to witness");
    assert_eq!(
        signed.input[3].witness.script_witness,
        vec![vec![0xab; 64]],
        "a witness already on the transaction survives"
    );
    assert_eq!(report.user_witnesses.len(), 1);

    // What the signer is told they are signing is exactly what moves.
    let flows = regulated_flows(&ctx, &tx, &prevouts, &alice, &[bob]).expect("resolves");
    assert_eq!(
        flows,
        vec![
            Flow::Input { index: 2, value: 20_000 },
            Flow::Payment { index: 2, to: bob, value: 20_000 },
        ]
    );
}

/// Every refusal names what is wrong, before anything is signed.
#[test]
fn refuses_what_it_cannot_prove() {
    let (alice_sk, alice) = key(1);
    let (_, bob) = key(2);
    let (carol_sk, _carol) = key(4);
    let ctx = test_ctx(&[alice, bob]);
    let req = transfer_req(alice, bob);
    let built = build_transfer(&ctx, &req).expect("builds");

    let err = cosign_transfer(&ctx, &built.tx, &built.prevouts, &carol_sk, &[bob], true)
        .expect_err("a key that owns no input has nothing to sign");
    assert!(err.contains("not C_U of the key given"), "{err}");

    let err = cosign_transfer(&ctx, &built.tx, &built.prevouts, &alice_sk, &[], true)
        .expect_err("a recipient nobody named cannot be proven");
    assert!(err.contains("no candidate's C_U"), "{err}");

    let err = cosign_transfer(&ctx, &built.tx, &built.prevouts[1..], &alice_sk, &[bob], true)
        .expect_err("prevouts must match the inputs");
    assert!(err.contains("prevouts"), "{err}");

    // A fee output that would burn the regulated asset is named, not left to
    // the BitMachine.
    let mut burn = built.tx.clone();
    let last = burn.output.len() - 1;
    assert!(burn.output[last].script_pubkey.is_empty(), "the builder's last output is the fee");
    burn.output[last].asset = confidential::Asset::Explicit(asset(A));
    let err = cosign_transfer(&ctx, &burn, &built.prevouts, &alice_sk, &[bob], true)
        .expect_err("a fee in the regulated asset burns it");
    assert!(err.contains("fee output") && err.contains("regulated asset"), "{err}");
    let err = regulated_flows(&ctx, &burn, &built.prevouts, &alice, &[bob])
        .expect_err("the summary refuses it the same way");
    assert!(err.contains("fee output"), "{err}");

    // A verifier of some other policy: same asset, different whitelist.
    let other = test_ctx(&[alice]);
    let err = cosign_transfer(&other, &built.tx, &built.prevouts, &alice_sk, &[bob], true)
        .expect_err("input 0 is another policy's verifier");
    assert!(err.contains("not this policy's verifier"), "{err}");
}

/// A lockup or a receive window the transaction does not claim through
/// nLockTime is refused by name rather than by the BitMachine.
#[test]
fn names_the_window_a_locktime_misses() {
    use opendamp::dmt::Entry;
    let (alice_sk, alice) = key(1);
    let (_, bob) = key(2);
    let (_, issuer) = key(9);
    let params = AssetParams { asset_a: asset(A), asset_v: asset(V), q: Q };
    let net = Net::regtest(BlockHash::from_str(&format!("{:064x}", 7u8)).unwrap());
    let entries = vec![
        Entry::unrestricted(alice.serialize()),
        Entry { key: bob.serialize(), send_after: 0, recv_after: 500 },
    ];
    let ctx = Ctx::with_policy(net, params, issuer, entries, &[], opendamp::programs::NO_LIMIT, 0)
        .expect("compiles");
    let mut req = transfer_req(alice, bob);
    req.locktime = 500;
    let built = build_transfer(&ctx, &req).expect("builds");
    cosign_transfer(&ctx, &built.tx, &built.prevouts, &alice_sk, &[bob], true)
        .expect("claiming the height satisfies the window");

    // The same transaction, composed by somebody who claimed no height.
    let mut early = built.tx.clone();
    early.lock_time = LockTime::ZERO;
    let err = cosign_transfer(&ctx, &early, &built.prevouts, &alice_sk, &[bob], true)
        .expect_err("bob cannot receive yet");
    assert!(err.contains("cannot receive before height 500"), "{err}");
}
