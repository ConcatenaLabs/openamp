package server

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/ConcatenaLabs/openamp/openampd/internal/elements"
	"github.com/ConcatenaLabs/openamp/openampd/internal/rpc"
	"github.com/ConcatenaLabs/openamp/openampd/internal/store"
)

// W-5, reworked for per-transfer confidentiality: a clawback sweep blinds the
// seized output whenever any swept input is blinded (the legacy per-asset flag
// is inert), a reissue request with "confidential": true blinds the minted
// enclave output, and the watch wallet reconciles its imports for EVERY
// registered (holder, asset) pair (plus one rescan) on startup.

// makeConfidential sets the LEGACY per-asset flag on a stored asset. Behavior
// never branches on it anymore; tests use it to prove the flag is inert.
func makeConfidential(t *testing.T, st *store.Store, assetID string) {
	t.Helper()
	if err := st.Update(func(s *store.State) error {
		s.Assets[assetID].Confidential = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// fundClawbackConf seeds the mock for a CONFIDENTIAL clawback: the holder's
// enclave coin is a blinded UTXO the watch wallet reports (with blinders), plus
// a fee coin and the change address. Mirrors fundClawback for the blinded case.
func fundClawbackConf(t *testing.T, s *Server, node *oa4Node, holder *store.User, asset *store.Asset, atoms uint64) {
	t.Helper()
	holderTree, err := s.treeFor(holder, asset)
	if err != nil {
		t.Fatal(err)
	}
	holderSpk := hex.EncodeToString(holderTree.ScriptPubKey())
	enclavePrev := &elements.Tx{Version: 2}
	enclavePrev.Out = append(enclavePrev.Out, enclaveOut(t, s, holder, asset, atoms))
	enclavePrev.NormalizeWitness()
	ePrevID := enclavePrev.TxID()
	node.rawTxs[ePrevID] = hex.EncodeToString(enclavePrev.Serialize())
	// The watch wallet unblinds the enclave coin: listunspent reports it with
	// its blinders (a confidential UTXO), never scantxoutset.
	node.confUnspent = append(node.confUnspent, rpc.ConfUnspent{
		TxID: ePrevID, Vout: 0, ScriptPubKey: holderSpk,
		Amount: float64(atoms) / 1e8, Asset: asset.ID,
		AmountBlinder: strings.Repeat("11", 32), AssetBlinder: strings.Repeat("22", 32),
	})

	feePrev := &elements.Tx{Version: 2}
	feePrev.Out = append(feePrev.Out, explicitOut(oa4FeeID, 100000, oa4FeeSpk))
	feePrev.NormalizeWitness()
	fPrevID := feePrev.TxID()
	node.rawTxs[fPrevID] = hex.EncodeToString(feePrev.Serialize())
	node.feeUnspent = []rpc.Unspent{{TxID: fPrevID, Vout: 0, Amount: 100000.0 / 1e8, Asset: oa4FeeID, ScriptPubKey: oa4FeeSpk, Spendable: true}}

	node.addrSpk[node.newAddr] = oa4ChgSpk
	node.broadcast = strings.Repeat("77", 32)
}

// TestW5_ConfidentialClawback_TwoPhase proves a two-phase clawback sweeping a
// BLINDED holder UTXO blinds the seized output and the fee change (the blinded
// amounts stay private through the seizure; nothing here depends on any asset
// flag — the asset is a plain transparent-issued one whose holder happens to
// hold a blinded coin), computes the issuer sighashes over the BLINDED tx (the
// pending build IS the blinded tx with a fixed txid), keeps the
// reason-before-signing property, and completes idempotently: a replay returns
// the same txid and never re-broadcasts.
func TestW5_ConfidentialClawback_TwoPhase(t *testing.T) {
	s, st, node := newM9Server(t, Config{FeeAsset: oa4FeeID, FeeSats: 100})
	issuer := regUser(t, st, nil)
	holder, _ := regUserWithKey(t, st)
	asset, issuerPriv := clawAsset(t, st, issuer.AID, true) // external issuer
	fundClawbackConf(t, s, node, holder, asset, 1000)

	code, out, body := callClawback(t, s, map[string]any{
		"asset": asset.ID, "holder_aid": holder.AID, "reason": "confidential seizure",
	})
	if code != 200 {
		t.Fatalf("confidential clawback build failed: %d %s", code, body)
	}
	if node.sends != 0 {
		t.Fatalf("build must broadcast nothing, saw %d sends", node.sends)
	}
	if !node.blindCalled {
		t.Fatal("a clawback sweeping a blinded input must blind the transaction")
	}
	if !logHasClawbackReason(t, st, "confidential seizure") {
		t.Fatal("the reason must be logged before any signature")
	}

	// The pending build is the BLINDED sweep: seized output (0) blinds to the
	// issuer's enclave key, the fee change (1) to a per-call blech32 output.
	id, _ := out["id"].(string)
	pc, ok := st.GetPendingClawback(id)
	if !ok {
		t.Fatal("no pending clawback persisted")
	}
	built, err := elements.DeserializeTx(mustHexBytes(pc.TxHex))
	if err != nil {
		t.Fatal(err)
	}
	issuerTree, _ := s.treeFor(issuer, asset)
	if hex.EncodeToString(built.Out[0].ScriptPubKey) != hex.EncodeToString(issuerTree.ScriptPubKey()) {
		t.Fatal("seized output does not pay the issuer enclave")
	}
	if !isBlindingNonce(built.Out[0].Nonce) {
		t.Fatalf("seized output must be blinded for a confidential asset, nonce %x", built.Out[0].Nonce)
	}
	if !isBlindingNonce(built.Out[1].Nonce) {
		t.Fatalf("fee-change output must be blinded (>=2 blinded outputs), nonce %x", built.Out[1].Nonce)
	}
	// The logged txid is the blinded tx's txid: the fixed txid a retry rebroadcasts.
	fixedTxid := built.TxID()

	// COMPLETE: issuer signs the blinded-tx sighashes; the broadcast bytes carry
	// the same txid as the pending build (witnesses don't change a txid).
	toSign, _ := out["to_sign"].([]any)
	sigs := signToSign(t, toSign[0], issuerPriv)
	code, out2, body := callClawbackComplete(t, s, id, map[string]any{"sigs": sigs})
	if code != 200 {
		t.Fatalf("confidential clawback complete failed: %d %s", code, body)
	}
	if node.sends != 1 {
		t.Fatalf("complete must broadcast exactly once, saw %d", node.sends)
	}
	sent, err := elements.DeserializeTx(mustHexBytes(node.lastBroadcast))
	if err != nil {
		t.Fatal(err)
	}
	if sent.TxID() != fixedTxid {
		t.Fatalf("broadcast txid %s != the pending build's fixed txid %s", sent.TxID(), fixedTxid)
	}

	// Retry (persist-before-broadcast idempotency): the identical tx, same txid,
	// no second broadcast.
	code, out2, body = callClawbackComplete(t, s, id, map[string]any{"sigs": sigs})
	if code != 200 || out2["idempotent"] != true {
		t.Fatalf("replay must be idempotent: %d %s", code, body)
	}
	if node.sends != 1 {
		t.Fatalf("replay must not re-broadcast, saw %d sends", node.sends)
	}
}

// TestW5_ConfidentialClawback_LegacySingleCall proves the legacy (server-held
// issuer key) clawback sweeping a blinded holder UTXO also blinds the seized
// output and still completes in one gated call. The LEGACY per-asset
// Confidential flag is set here on purpose: it must be inert — the blinding
// decision keys on the swept inputs, and everything still works with it set.
func TestW5_ConfidentialClawback_LegacySingleCall(t *testing.T) {
	s, st, node := newM9Server(t, Config{FeeAsset: oa4FeeID, FeeSats: 100})
	issuer := regUser(t, st, nil)
	holder, _ := regUserWithKey(t, st)
	asset, _ := clawAsset(t, st, issuer.AID, false) // server holds the issuer key
	makeConfidential(t, st, asset.ID)               // legacy flag: inert
	fundClawbackConf(t, s, node, holder, asset, 1000)

	code, out, body := callClawback(t, s, map[string]any{
		"asset": asset.ID, "holder_aid": holder.AID, "reason": "legacy confidential sweep",
	})
	if code != 200 {
		t.Fatalf("legacy confidential clawback failed: %d %s", code, body)
	}
	if out["txid"] != node.broadcast {
		t.Fatalf("legacy clawback must broadcast in one call, got %s", body)
	}
	if !node.blindCalled {
		t.Fatal("a clawback sweeping a blinded input must blind the transaction")
	}
	sent, err := elements.DeserializeTx(mustHexBytes(node.lastBroadcast))
	if err != nil {
		t.Fatal(err)
	}
	if !isBlindingNonce(sent.Out[0].Nonce) {
		t.Fatalf("seized output must be blinded, nonce %x", sent.Out[0].Nonce)
	}
}

// TestW5_WatchReconcileImportsAndRescansOnce proves the startup reconcile
// re-imports EVERY registered (holder, asset) pair idempotently — the asset
// here is an ordinary transparent-issued one, because under per-transfer
// confidentiality any enclave may hold blinded coins — and runs exactly one
// rescan pass, and that startWatchReconcile is bounded to one run per process
// regardless of how often it is invoked.
func TestW5_WatchReconcileImportsAndRescansOnce(t *testing.T) {
	s, st, node := newM9Server(t, Config{FeeAsset: oa4FeeID, FeeSats: 100})
	issuer := regUser(t, st, nil)
	regUser(t, st, nil) // a second registered user
	clawAsset(t, st, issuer.AID, false)

	// Direct (synchronous) run: 2 users x 1 asset = 2 pairs, each
	// re-imported (script + blinding key), then ONE rescan.
	s.reconcileWatchWallet()
	if node.imports.Load() != 2 || node.blindImports.Load() != 2 {
		t.Fatalf("expected 2 script + 2 blinding-key imports, got %d/%d", node.imports.Load(), node.blindImports.Load())
	}
	if node.rescans.Load() != 1 {
		t.Fatalf("expected exactly 1 rescan pass, got %d", node.rescans.Load())
	}

	// The once-guard: invoking the startup hook repeatedly launches at most one
	// further (background) run.
	s.startWatchReconcile()
	s.startWatchReconcile()
	deadline := time.Now().Add(2 * time.Second)
	for node.rescans.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // give a hypothetical second run time to appear
	if got := node.rescans.Load(); got != 2 {
		t.Fatalf("startWatchReconcile must run at most once per process, saw %d total rescans", got)
	}
}

// TestW5_WatchReconcileNoPairsIsNoop proves a deployment with no registered
// (holder, asset) pairs — here, no assets at all — neither imports nor rescans.
// (With per-transfer confidentiality there is no such thing as a "deployment
// without confidential assets": every pair is reconciled once any asset exists.)
func TestW5_WatchReconcileNoPairsIsNoop(t *testing.T) {
	s, st, node := newM9Server(t, Config{FeeAsset: oa4FeeID, FeeSats: 100})
	regUser(t, st, nil) // a user, but no assets: zero pairs

	s.reconcileWatchWallet()
	if node.imports.Load() != 0 || node.blindImports.Load() != 0 || node.rescans.Load() != 0 {
		t.Fatalf("no enclave pairs: expected no imports/rescan, got %d/%d/%d",
			node.imports.Load(), node.blindImports.Load(), node.rescans.Load())
	}
}
