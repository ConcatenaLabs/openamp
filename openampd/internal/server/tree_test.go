package server

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"

	"github.com/ConcatenaLabs/openamp/openampd/internal/elements"
	"github.com/ConcatenaLabs/openamp/openampd/internal/server/treefake"
	"github.com/ConcatenaLabs/openamp/openampd/internal/store"
)

// The test binary is also the stand-in for arca-enclave (treefake).
func TestMain(m *testing.M) {
	treefake.Main()
	os.Exit(m.Run())
}

const treeOperator = "1111111111111111111111111111111111111111111111111111111111111111"

type treeFixture struct {
	s      *Server
	st     *store.Store
	node   *oa4Node
	asset  *store.Asset
	issuer *store.User
	h      []*store.User // registered holders
}

// newTreeFixture is a server with the fake tool, a clawback-elected asset whose
// issuer key the server holds (the demo), its tree enabled, and four holders.
func newTreeFixture(t *testing.T) *treeFixture {
	t.Helper()
	s, st, node := newM9Server(t, Config{})
	s.treeTool = execTreeTool{path: treefake.Path()}
	issuer := regUser(t, st, nil)
	asset, _ := clawAsset(t, st, issuer.AID, false)
	f := &treeFixture{s: s, st: st, node: node, asset: asset, issuer: issuer}
	for i := 0; i < 4; i++ {
		f.h = append(f.h, regUser(t, st, nil))
	}
	setHeight(t, st, 100)
	code, body := f.post(t, s.handleTreeEnable, "/v1/issuer/tree", map[string]any{"asset": asset.ID, "operator": treeOperator}, nil)
	if code != 200 {
		t.Fatalf("enable: %d %s", code, body)
	}
	st.View(func(x *store.State) { f.asset = x.Assets[asset.ID] })
	return f
}

func (f *treeFixture) post(t *testing.T, h func(w http.ResponseWriter, r *http.Request), path string, body any, pathValues map[string]string) (int, string) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", path, bytes.NewReader(b))
	for k, v := range pathValues {
		req.SetPathValue(k, v)
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec.Code, rec.Body.String()
}

// seedLeaf puts a live leaf of holder u in the register.
func (f *treeFixture) seedLeaf(t *testing.T, u *store.User, salt string, atoms uint64) {
	t.Helper()
	if err := f.st.Update(func(st *store.State) error {
		st.TreeLeaves[salt] = &store.TreeLeaf{Salt: salt, Asset: f.asset.ID, HolderAID: u.AID, Holder: u.Pubkeys[0],
			Atoms: atoms, State: store.LeafLive, ExitScript: "5120" + strings.Repeat("ee", 32),
			Scripts: []store.LeafScript{{ScriptPubKey: "5120" + strings.Repeat("ee", 32)}}, Height: -1}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

type treeOut struct {
	u     *store.User
	value string
	nonce string
}

// transferBody is a tree transfer of coins to outs, with deliberately false
// terms: the server must replace them with the asset's.
func (f *treeFixture) transferBody(coins []treefake.Coin, outs []treeOut) map[string]any {
	var ins []map[string]any
	for _, c := range coins {
		ins = append(ins, map[string]any{"coin": treefake.CoinHex(c), "checkpoint_value": c.Value})
	}
	var os_ []map[string]any
	for _, o := range outs {
		os_ = append(os_, map[string]any{"asset": f.asset.ID, "value": o.value, "holder": o.u.Pubkeys[0],
			"owner_nonce": o.nonce, "creator_nonce": strings.Repeat("cc", 32), "exit_delay_units": 2})
	}
	return map[string]any{"asset": f.asset.ID, "transfer": map[string]any{
		"genesis": strings.Repeat("00", 32), "operator": strings.Repeat("22", 32), "policy": strings.Repeat("33", 32),
		"clawback": nil, "inputs": ins, "outputs": os_,
	}}
}

func (f *treeFixture) transfer(t *testing.T, coins []treefake.Coin, outs []treeOut) (int, string) {
	return f.post(t, f.s.handleTreeTransfer, "/v1/issuer/tree/transfer", f.transferBody(coins, outs), nil)
}

func salt(b byte) string { return strings.Repeat(hex.EncodeToString([]byte{b}), 32) }

func leafState(t *testing.T, st *store.Store, salt string) string {
	t.Helper()
	var s string
	st.View(func(x *store.State) {
		if l, ok := x.TreeLeaves[salt]; ok {
			s = l.State
		}
	})
	return s
}

func wantRefused(t *testing.T, code int, body, want string) {
	t.Helper()
	if code == 200 || !strings.Contains(body, want) {
		t.Fatalf("want a refusal containing %q, got %d %s", want, code, body)
	}
	t.Logf("refused %d: %s", code, strings.TrimSpace(body))
}

func TestTree_NoToolAnswers501(t *testing.T) {
	s, st, node := newM9Server(t, Config{})
	issuer := regUser(t, st, nil)
	asset, _ := clawAsset(t, st, issuer.AID, false)
	f := &treeFixture{s: s, st: st, node: node, asset: asset}
	for _, c := range []struct {
		h    func(w http.ResponseWriter, r *http.Request)
		body any
	}{
		{s.handleTreeEnable, map[string]any{"asset": asset.ID, "operator": treeOperator}},
		{s.handleTreeTransfer, map[string]any{"asset": asset.ID, "transfer": map[string]any{}}},
		{s.handleTreeClawback, map[string]any{"asset": asset.ID, "salt": salt(1), "tx": "00", "input": 0, "reason": "r"}},
	} {
		code, body := f.post(t, c.h, "/", c.body, nil)
		if code != 501 || !strings.Contains(body, "runs no tree tool") {
			t.Fatalf("want 501, got %d %s", code, body)
		}
	}
	// A co-sign naming a tree output.
	holder := regUser(t, st, nil)
	tx := f.boardTx(t, holder, "5120"+strings.Repeat("ab", 32), 1000)
	code, body := f.cosignBoard(t, holder, tx, map[string]any{})
	if code != 501 || !strings.Contains(body, "runs no tree tool") {
		t.Fatalf("want 501, got %d %s", code, body)
	}
}

// boardAnswer is a correct reading of a board of the fixture's tree for u.
func (f *treeFixture) boardAnswer(u *store.User, spk string, value string, salt string) map[string]any {
	claw := strings.ToLower(f.asset.IssuerPub)
	return map[string]any{
		"template": "enclave-1", "script_pubkey": spk, "leaf_script_pubkey": "5120" + strings.Repeat("dd", 32),
		"asset": f.asset.ID, "value": value, "holder": u.Pubkeys[0], "policy": strings.ToLower(f.asset.PolicyPub),
		"clawback": claw, "operator": treeOperator, "genesis": f.s.genesisDisplay(), "salt": salt,
		"claw_control": "c4" + strings.Repeat("01", 32), "leaf_claw_control": "c4" + strings.Repeat("02", 32),
	}
}

// boardTx spends u's enclave coin of 1000 into one board output.
func (f *treeFixture) boardTx(t *testing.T, u *store.User, boardSpk string, value uint64) *elements.Tx {
	t.Helper()
	prev := &elements.Tx{Version: 2, Out: []*elements.TxOut{enclaveOut(t, f.s, u, f.asset, value)}}
	prev.NormalizeWitness()
	f.node.rawTxs[prev.TxID()] = hex.EncodeToString(prev.Serialize())
	tx := &elements.Tx{Version: 2}
	tx.In = []*elements.TxIn{{Prevout: elements.OutPoint{Hash: internalHash(prev.TxID()), N: 0}}}
	tx.Out = []*elements.TxOut{explicitOut(f.asset.ID, value, boardSpk)}
	tx.NormalizeWitness()
	return tx
}

func (f *treeFixture) cosignBoard(t *testing.T, u *store.User, tx *elements.Tx, answer map[string]any) (int, string) {
	return f.post(t, f.s.handleCosign, "/v1/cosign", map[string]any{"tx": hex.EncodeToString(tx.Serialize()),
		"asset": f.asset.ID, "sender_aid": u.AID, "inputs": []int{0},
		"tree_outputs": []map[string]any{{"output": 0, "record": treefake.BoardHex(answer)}}}, nil)
}

func TestTree_AdmissionOfABoard(t *testing.T) {
	f := newTreeFixture(t)
	h1 := f.h[0]
	spk := "5120" + strings.Repeat("ab", 32)
	tx := f.boardTx(t, h1, spk, 1000)

	// Without the board named, the output is no enclave of anyone.
	code, body := f.post(t, f.s.handleCosign, "/v1/cosign", map[string]any{"tx": hex.EncodeToString(tx.Serialize()),
		"asset": f.asset.ID, "sender_aid": h1.AID, "inputs": []int{0}}, nil)
	wantRefused(t, code, body, "restricted asset to an out-of-enclave destination")

	bad := func(mut func(a map[string]any)) map[string]any {
		a := f.boardAnswer(h1, spk, "1000", salt(0x10))
		mut(a)
		return a
	}
	cases := []struct {
		name   string
		answer map[string]any
		want   string
	}{
		{"wrong operator", bad(func(a map[string]any) { a["operator"] = strings.Repeat("22", 32) }), "and the asset's tree is operator"},
		{"wrong policy", bad(func(a map[string]any) { a["policy"] = strings.Repeat("33", 32) }), "and the asset's is"},
		{"no clawback leaf where the asset elected one", bad(func(a map[string]any) { a["clawback"] = nil }), "its leaf's clawback key is none"},
		{"another clawback key", bad(func(a map[string]any) { a["clawback"] = strings.Repeat("44", 32) }), "and the asset's election is"},
		{"unregistered holder", bad(func(a map[string]any) { a["holder"] = strings.Repeat("55", 32) }), "which no account here registered"},
		{"another script", bad(func(a map[string]any) { a["script_pubkey"] = "5120" + strings.Repeat("ac", 32) }), "its script is not the board its record builds"},
		{"another value", bad(func(a map[string]any) { a["value"] = "999" }), "it holds 1000 atoms, and its record's board holds 999"},
		{"another template", bad(func(a map[string]any) { a["template"] = "vtxo-1" }), "a restricted asset's tree holds enclave-1 leaves only"},
		{"another chain", bad(func(a map[string]any) { a["genesis"] = strings.Repeat("99", 32) }), "not this one's"},
		{"the tool refuses the record", bad(func(a map[string]any) { a["error"] = "the record is a board of no restricted asset" }), "arca-enclave: the record is a board of no restricted asset"},
	}
	for _, c := range cases {
		code, body := f.cosignBoard(t, h1, tx, c.answer)
		t.Run(c.name, func(t *testing.T) { wantRefused(t, code, body, c.want) })
	}
	if n := len(func() map[string]*store.TreeLeaf {
		var m map[string]*store.TreeLeaf
		f.st.View(func(x *store.State) { m = x.TreeLeaves })
		return m
	}()); n != 0 {
		t.Fatalf("a refused admission registered %d leaves", n)
	}

	code, body = f.cosignBoard(t, h1, tx, f.boardAnswer(h1, spk, "1000", salt(0x10)))
	if code != 200 || !strings.Contains(body, "policy_sig") {
		t.Fatalf("admission: %d %s", code, body)
	}
	if s := leafState(t, f.st, salt(0x10)); s != store.LeafBoarding {
		t.Fatalf("an admitted board is boarding until its transaction is in a block, got %q", s)
	}
	// The same co-sign again signs again and registers nothing more.
	if code, body := f.cosignBoard(t, h1, tx, f.boardAnswer(h1, spk, "1000", salt(0x10))); code != 200 {
		t.Fatalf("repeat: %d %s", code, body)
	}
	// Another board at the same salt is refused.
	tx2 := f.boardTx(t, h1, spk, 1000)
	tx2.LockTime = 7
	code, body = f.cosignBoard(t, h1, tx2, f.boardAnswer(h1, spk, "1000", salt(0x10)))
	wantRefused(t, code, body, "is in the register already")

	// The follower: in a block it is live, and a reorganisation that takes
	// the block away makes it boarding again.
	f.st.Update(func(st *store.State) error {
		followTree(st, -1, map[string]int64{tx.TxID(): 101})
		return nil
	})
	if s := leafState(t, f.st, salt(0x10)); s != store.LeafLive {
		t.Fatalf("after its block: %q", s)
	}
	f.st.Update(func(st *store.State) error { followTree(st, 101, map[string]int64{}); return nil })
	if s := leafState(t, f.st, salt(0x10)); s != store.LeafBoarding {
		t.Fatalf("after a reorganisation: %q", s)
	}
	// Live leaves count as holdings.
	f.st.Update(func(st *store.State) error { followTree(st, -1, map[string]int64{tx.TxID(): 102}); return nil })
	bal, err := f.s.holderBalances(f.asset)
	if err != nil || bal[h1.AID] != 1000 {
		t.Fatalf("balances: %v %v", bal, err)
	}
}

func verifySig(t *testing.T, pubHex string, digestHex, sigHex string) {
	t.Helper()
	pub, err := schnorr.ParsePubKey(mustHexBytes(pubHex))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := schnorr.ParseSignature(mustHexBytes(sigHex))
	if err != nil {
		t.Fatal(err)
	}
	var d [32]byte
	copy(d[:], mustHexBytes(digestHex))
	m := treeCosignMessage(d)
	if !sig.Verify(m[:], pub) {
		t.Fatalf("signature %s does not verify under %s over the tagged digest", sigHex, pubHex)
	}
}

func TestTree_TransferApprovedRepeatedDropped(t *testing.T) {
	f := newTreeFixture(t)
	h1, h2 := f.h[0], f.h[1]
	f.seedLeaf(t, h1, salt(1), 1000)
	coin := treefake.Coin{Salt: salt(1), Holder: h1.Pubkeys[0], Value: "1000"}
	outs := []treeOut{{h2, "300", salt(0x21)}, {h1, "700", salt(0x22)}}
	code, body := f.transfer(t, []treefake.Coin{coin}, outs)
	if code != 200 {
		t.Fatalf("transfer: %d %s", code, body)
	}
	var ans struct {
		ID         string                `json:"id"`
		Policy     string                `json:"policy"`
		Signatures []store.TreeSignature `json:"signatures"`
	}
	json.Unmarshal([]byte(body), &ans)
	if len(ans.Signatures) != 2 {
		t.Fatalf("want two signatures, one per message, got %s", body)
	}
	// The digests are the tool's under the ASSET's terms, not the caller's.
	var req treefake.Request
	in, _ := json.Marshal(map[string]any{"genesis": f.s.genesisDisplay(), "operator": treeOperator,
		"policy": f.asset.Tree.Policy, "clawback": f.asset.Tree.Clawback,
		"inputs": []any{}, "outputs": f.transferBody(nil, outs)["transfer"].(map[string]any)["outputs"]})
	json.Unmarshal(in, &req)
	cd, rd := treefake.Digests(&req, salt(1))
	if ans.Signatures[0].Digest != cd || ans.Signatures[1].Digest != rd {
		t.Fatalf("digests %s %s, want %s %s (the server must override the caller's terms)", ans.Signatures[0].Digest, ans.Signatures[1].Digest, cd, rd)
	}
	for _, s := range ans.Signatures {
		verifySig(t, f.asset.PolicyPub, s.Digest, s.Signature)
	}
	if leafState(t, f.st, salt(1)) != store.LeafSpent || leafState(t, f.st, salt(0x21)) != store.LeafLive || leafState(t, f.st, salt(0x22)) != store.LeafLive {
		t.Fatal("the register did not follow the transfer")
	}
	var records int
	f.st.View(func(st *store.State) {
		for _, r := range st.Transfers {
			if r.Kind == "tree" {
				records++
				if r.Atoms != 300 || r.Height != 100 || r.SenderAID != h1.AID {
					t.Fatalf("velocity record %+v", r)
				}
			}
		}
	})
	if records != 1 {
		t.Fatalf("%d velocity records", records)
	}
	// The same request again: the same answer, nothing recorded twice.
	code2, body2 := f.transfer(t, []treefake.Coin{coin}, outs)
	if code2 != 200 || body2 != body {
		t.Fatalf("repeat: %d %s, want %s", code2, body2, body)
	}
	// Spending a spent leaf in another transfer is refused.
	code, body = f.transfer(t, []treefake.Coin{coin}, []treeOut{{h2, "1000", salt(0x23)}})
	wantRefused(t, code, body, "which is spent")

	// Dropped: the input is live again, the outputs and the record gone.
	code, body = f.post(t, f.s.handleTreeTransferDrop, "/", nil, map[string]string{"id": ans.ID})
	if code != 200 {
		t.Fatalf("drop: %d %s", code, body)
	}
	if leafState(t, f.st, salt(1)) != store.LeafLive || leafState(t, f.st, salt(0x21)) != "" {
		t.Fatal("drop did not give the input back")
	}
	code, body = f.post(t, f.s.handleTreeTransferDrop, "/", nil, map[string]string{"id": ans.ID})
	wantRefused(t, code, body, "no tree transfer")

	// Approved again, then its output spent onward: no longer dropped.
	code, body = f.transfer(t, []treefake.Coin{coin}, outs)
	if code != 200 {
		t.Fatalf("again: %d %s", code, body)
	}
	code, body = f.transfer(t, []treefake.Coin{{Salt: salt(0x21), Holder: h2.Pubkeys[0], Value: "300"}},
		[]treeOut{{h1, "300", salt(0x24)}})
	if code != 200 {
		t.Fatalf("onward: %d %s", code, body)
	}
	code, body = f.post(t, f.s.handleTreeTransferDrop, "/", nil, map[string]string{"id": ans.ID})
	wantRefused(t, code, body, "the transfer was used, and is no longer dropped")
}

func TestTree_TransferRefusals(t *testing.T) {
	f := newTreeFixture(t)
	h1, h2, h3 := f.h[0], f.h[1], f.h[2]
	f.seedLeaf(t, h1, salt(1), 1000)
	f.seedLeaf(t, h2, salt(2), 500)
	c1 := treefake.Coin{Salt: salt(1), Holder: h1.Pubkeys[0], Value: "1000"}

	code, body := f.transfer(t, []treefake.Coin{{Salt: salt(9), Holder: h1.Pubkeys[0], Value: "1"}}, []treeOut{{h2, "1", salt(0x30)}})
	wantRefused(t, code, body, "which the register does not hold")
	code, body = f.transfer(t, []treefake.Coin{c1, {Salt: salt(2), Holder: h2.Pubkeys[0], Value: "500"}}, []treeOut{{h3, "1500", salt(0x30)}})
	wantRefused(t, code, body, "one tree transfer has one sender")
	code, body = f.transfer(t, []treefake.Coin{c1}, []treeOut{{h2, "999", salt(0x30)}})
	wantRefused(t, code, body, "the outputs take 999 of the inputs' 1000 atoms")
	// A checkpoint that keeps less than the coin.
	b := f.transferBody([]treefake.Coin{c1}, []treeOut{{h2, "1000", salt(0x30)}})
	b["transfer"].(map[string]any)["inputs"].([]map[string]any)[0]["checkpoint_value"] = "990"
	code, body = f.post(t, f.s.handleTreeTransfer, "/", b, nil)
	wantRefused(t, code, body, "a checkpoint of a restricted coin keeps the whole coin")
	// An unregistered receiver.
	stranger := &store.User{AID: "x", Pubkeys: []string{strings.Repeat("66", 32)}}
	code, body = f.transfer(t, []treefake.Coin{c1}, []treeOut{{stranger, "1000", salt(0x30)}})
	wantRefused(t, code, body, "which no account here registered")
	// The tool's refusal.
	code, body = f.transfer(t, []treefake.Coin{{Error: "coin record of another template"}}, []treeOut{{h2, "1", salt(0x30)}})
	wantRefused(t, code, body, "arca-enclave: coin record of another template")
	// Frozen sender, frozen receiver.
	f.st.Update(func(st *store.State) error { st.Users[h1.AID].Frozen = true; return nil })
	code, body = f.transfer(t, []treefake.Coin{c1}, []treeOut{{h2, "1000", salt(0x30)}})
	wantRefused(t, code, body, "sender frozen")
	f.st.Update(func(st *store.State) error {
		st.Users[h1.AID].Frozen = false
		st.Users[h2.AID].Frozen = true
		return nil
	})
	code, body = f.transfer(t, []treefake.Coin{c1}, []treeOut{{h2, "1000", salt(0x30)}})
	wantRefused(t, code, body, "recipient "+h2.AID+" frozen")
	f.st.Update(func(st *store.State) error { st.Users[h2.AID].Frozen = false; return nil })
	if leafState(t, f.st, salt(1)) != store.LeafLive {
		t.Fatal("a refused transfer spent its input")
	}
}

// One reassignment refused for each rule, with the words checkTransfer uses.
func TestTree_TransferRefusedForEachRule(t *testing.T) {
	setRules := func(f *treeFixture, r store.Rules) {
		f.st.Update(func(st *store.State) error { st.Assets[f.asset.ID].Rules = r; return nil })
	}
	t.Run("category", func(t *testing.T) {
		f := newTreeFixture(t)
		f.seedLeaf(t, f.h[0], salt(1), 1000)
		f.st.Update(func(st *store.State) error { st.Users[f.h[2].AID].Categories = []string{"accredited"}; return nil })
		setRules(f, store.Rules{AllowedCategories: []string{"accredited"}})
		code, body := f.transfer(t, []treefake.Coin{{Salt: salt(1), Holder: f.h[0].Pubkeys[0], Value: "1000"}},
			[]treeOut{{f.h[1], "100", salt(0x31)}, {f.h[0], "900", salt(0x32)}})
		wantRefused(t, code, body, "recipient "+f.h[1].AID+" lacks a permitted category")
		code, body = f.transfer(t, []treefake.Coin{{Salt: salt(1), Holder: f.h[0].Pubkeys[0], Value: "1000"}},
			[]treeOut{{f.h[2], "100", salt(0x31)}, {f.h[0], "900", salt(0x32)}})
		if code != 200 {
			t.Fatalf("a permitted category is refused: %d %s", code, body)
		}
	})
	t.Run("lock-in", func(t *testing.T) {
		f := newTreeFixture(t)
		f.seedLeaf(t, f.h[0], salt(1), 1000)
		setRules(f, store.Rules{LockinUntilHeight: 500})
		code, body := f.transfer(t, []treefake.Coin{{Salt: salt(1), Holder: f.h[0].Pubkeys[0], Value: "1000"}},
			[]treeOut{{f.h[1], "1000", salt(0x31)}})
		wantRefused(t, code, body, "asset is locked in until height 500 (current 100)")
	})
	t.Run("velocity", func(t *testing.T) {
		f := newTreeFixture(t)
		f.seedLeaf(t, f.h[0], salt(1), 1000)
		setRules(f, store.Rules{VelocityWindowBlocks: 50, VelocityMaxAtoms: 500})
		code, body := f.transfer(t, []treefake.Coin{{Salt: salt(1), Holder: f.h[0].Pubkeys[0], Value: "1000"}},
			[]treeOut{{f.h[1], "400", salt(0x31)}, {f.h[0], "600", salt(0x32)}})
		if code != 200 {
			t.Fatalf("first: %d %s", code, body)
		}
		code, body = f.transfer(t, []treefake.Coin{{Salt: salt(0x32), Holder: f.h[0].Pubkeys[0], Value: "600"}},
			[]treeOut{{f.h[1], "200", salt(0x33)}, {f.h[0], "400", salt(0x34)}})
		wantRefused(t, code, body, "velocity limit: 400 atoms in window plus 200 exceeds 500")
		// Out of the window it passes, as an on-chain transfer's would.
		setHeight(t, f.st, 151)
		code, body = f.transfer(t, []treefake.Coin{{Salt: salt(0x32), Holder: f.h[0].Pubkeys[0], Value: "600"}},
			[]treeOut{{f.h[1], "200", salt(0x33)}, {f.h[0], "400", salt(0x34)}})
		if code != 200 {
			t.Fatalf("after the window: %d %s", code, body)
		}
	})
	t.Run("holder cap", func(t *testing.T) {
		f := newTreeFixture(t)
		f.seedLeaf(t, f.h[0], salt(1), 1000)
		f.seedLeaf(t, f.h[1], salt(2), 10)
		setRules(f, store.Rules{HolderCap: 2})
		code, body := f.transfer(t, []treefake.Coin{{Salt: salt(1), Holder: f.h[0].Pubkeys[0], Value: "1000"}},
			[]treeOut{{f.h[2], "100", salt(0x31)}, {f.h[0], "900", salt(0x32)}})
		wantRefused(t, code, body, "holder cap 2 would be exceeded (3 holders)")
		// To a holder already counted it passes.
		code, body = f.transfer(t, []treefake.Coin{{Salt: salt(1), Holder: f.h[0].Pubkeys[0], Value: "1000"}},
			[]treeOut{{f.h[1], "100", salt(0x31)}, {f.h[0], "900", salt(0x32)}})
		if code != 200 {
			t.Fatalf("within the cap: %d %s", code, body)
		}
	})
	t.Run("vesting", func(t *testing.T) {
		f := newTreeFixture(t)
		f.seedLeaf(t, f.h[0], salt(1), 1000)
		setRules(f, store.Rules{Vesting: []store.VestingEntry{{AID: f.h[0].AID, Atoms: 900, UntilHeight: 500}}})
		code, body := f.transfer(t, []treefake.Coin{{Salt: salt(1), Holder: f.h[0].Pubkeys[0], Value: "1000"}},
			[]treeOut{{f.h[1], "200", salt(0x31)}, {f.h[0], "800", salt(0x32)}})
		wantRefused(t, code, body, "vesting: 900 atoms locked until height 500")
		code, body = f.transfer(t, []treefake.Coin{{Salt: salt(1), Holder: f.h[0].Pubkeys[0], Value: "1000"}},
			[]treeOut{{f.h[1], "100", salt(0x31)}, {f.h[0], "900", salt(0x32)}})
		if code != 200 {
			t.Fatalf("the unvested part: %d %s", code, body)
		}
	})
}

// exitTx spends a coin at leafSpk and pays payTo atoms at output 0.
func (f *treeFixture) exitTx(t *testing.T, leafSpk string, payTo []byte, atoms uint64, confs int64) *elements.Tx {
	t.Helper()
	prev := &elements.Tx{Version: 2, Out: []*elements.TxOut{explicitOut(f.asset.ID, atoms, leafSpk)}}
	prev.NormalizeWitness()
	f.node.rawTxs[prev.TxID()] = hex.EncodeToString(prev.Serialize())
	tx := &elements.Tx{Version: 2}
	tx.In = []*elements.TxIn{{Prevout: elements.OutPoint{Hash: internalHash(prev.TxID()), N: 0}}}
	tx.Out = []*elements.TxOut{{Asset: elements.ExplicitAsset(elements.MustHex32(f.asset.ID)), Value: elements.ExplicitValue(atoms),
		Nonce: elements.NullNonce(), ScriptPubKey: payTo}}
	tx.NormalizeWitness()
	f.node.rawTxs[tx.TxID()] = hex.EncodeToString(tx.Serialize())
	f.node.confs[tx.TxID()] = confs
	return tx
}

func TestTree_ExitReported(t *testing.T) {
	f := newTreeFixture(t)
	h1, h2 := f.h[0], f.h[1]
	f.node.tip = 120
	f.seedLeaf(t, h1, salt(1), 1000)
	leafSpk := "5120" + strings.Repeat("ee", 32)
	enclave, _ := f.s.treeFor(h1, f.asset)
	other, _ := f.s.treeFor(h2, f.asset)

	exited := func(tx *elements.Tx) (int, string) {
		return f.post(t, f.s.handleTreeExited, "/", map[string]any{"txid": tx.TxID()}, map[string]string{"salt": salt(1)})
	}
	code, body := exited(f.exitTx(t, leafSpk, other.ScriptPubKey(), 1000, 3))
	wantRefused(t, code, body, "is no exit of leaf")
	code, body = exited(f.exitTx(t, leafSpk, enclave.ScriptPubKey(), 999, 3))
	wantRefused(t, code, body, "is no exit of leaf")
	code, body = exited(f.exitTx(t, "5120"+strings.Repeat("ef", 32), enclave.ScriptPubKey(), 1000, 3))
	wantRefused(t, code, body, "is no exit of leaf")
	code, body = exited(f.exitTx(t, leafSpk, enclave.ScriptPubKey(), 1000, 0))
	wantRefused(t, code, body, "is in no block yet")
	good := f.exitTx(t, leafSpk, enclave.ScriptPubKey(), 1000, 3)
	code, body = exited(good)
	if code != 200 || leafState(t, f.st, salt(1)) != store.LeafExited {
		t.Fatalf("exit: %d %s", code, body)
	}
	code, body = exited(good)
	wantRefused(t, code, body, "is exited, not live")
	// A reorganisation that takes the exit's block away reopens the leaf.
	f.st.Update(func(st *store.State) error { followTree(st, 118, map[string]int64{}); return nil })
	if leafState(t, f.st, salt(1)) != store.LeafLive {
		t.Fatal("a reorganised exit left its leaf closed")
	}
}

func TestTree_Clawback(t *testing.T) {
	f := newTreeFixture(t)
	h1 := f.h[0]
	leafSpk := "5120" + strings.Repeat("ee", 32)
	f.seedLeaf(t, h1, salt(1), 1000)
	f.st.Update(func(st *store.State) error {
		st.TreeLeaves[salt(1)].Scripts[0].ClawControl = "c4" + strings.Repeat("03", 32)
		return nil
	})
	issuerEnclave, _ := f.s.treeFor(f.issuer, f.asset)
	holderEnclave, _ := f.s.treeFor(h1, f.asset)
	claw := func(tx *elements.Tx, s string) (int, string) {
		return f.post(t, f.s.handleTreeClawback, "/", map[string]any{"asset": f.asset.ID, "salt": s,
			"tx": hex.EncodeToString(tx.Serialize()), "input": 0, "reason": "court order 7"}, nil)
	}
	code, body := claw(f.exitTx(t, leafSpk, holderEnclave.ScriptPubKey(), 1000, 0), salt(1))
	wantRefused(t, code, body, "elsewhere than the issuer's enclave")
	code, body = claw(f.exitTx(t, "5120"+strings.Repeat("ef", 32), issuerEnclave.ScriptPubKey(), 1000, 0), salt(1))
	wantRefused(t, code, body, "spends no output leaf")
	tx := f.exitTx(t, leafSpk, issuerEnclave.ScriptPubKey(), 1000, 0)
	code, body = claw(tx, salt(1))
	if code != 200 {
		t.Fatalf("clawback: %d %s", code, body)
	}
	var ans map[string]any
	json.Unmarshal([]byte(body), &ans)
	if ans["issuer_sig"] == nil || ans["control"] != "c4"+strings.Repeat("03", 32) {
		t.Fatalf("answer %s", body)
	}
	// Both halves verify over the claw leaf's sighash.
	spent, _ := f.s.spentOutputs(tx)
	leaf := elements.CheckSigPair(elements.MustHex32(*f.asset.Tree.Clawback), elements.MustHex32(f.asset.Tree.Policy))
	sh, _ := elements.TaprootSighash(tx, spent, elements.SighashDefault, f.s.genesis, 0, leaf)
	for key, sig := range map[string]string{f.asset.PolicyPub: ans["policy_sig"].(string), *f.asset.Tree.Clawback: ans["issuer_sig"].(string)} {
		pub, _ := schnorr.ParsePubKey(mustHexBytes(key))
		s, _ := schnorr.ParseSignature(mustHexBytes(sig))
		if !s.Verify(sh[:], pub) {
			t.Fatalf("a clawback signature does not verify under %s", key)
		}
	}
	if leafState(t, f.st, salt(1)) != store.LeafClawed {
		t.Fatal("not clawed")
	}
	code, body = claw(tx, salt(1))
	wantRefused(t, code, body, "is clawed: only a live leaf")
}

func TestTree_NoClawbackWhereNoneWasElected(t *testing.T) {
	s, st, _ := newM9Server(t, Config{})
	s.treeTool = execTreeTool{path: treefake.Path()}
	issuer := regUser(t, st, nil)
	asset := oa7Asset(t, st, issuer.AID) // no clawback
	f := &treeFixture{s: s, st: st, asset: asset, issuer: issuer}
	code, body := f.post(t, s.handleTreeEnable, "/", map[string]any{"asset": asset.ID, "operator": treeOperator}, nil)
	if code != 200 || !strings.Contains(body, `"clawback":null`) {
		t.Fatalf("enable: %d %s", code, body)
	}
	code, body = f.post(t, s.handleTreeClawback, "/", map[string]any{"asset": asset.ID, "salt": salt(1), "tx": "00", "input": 0, "reason": "r"}, nil)
	wantRefused(t, code, body, "this asset was issued without a clawback leaf")
}

func TestTree_OperatorFixedWhileLeavesAreHeld(t *testing.T) {
	f := newTreeFixture(t)
	f.seedLeaf(t, f.h[0], salt(1), 10)
	code, body := f.post(t, f.s.handleTreeEnable, "/", map[string]any{"asset": f.asset.ID, "operator": strings.Repeat("22", 32)}, nil)
	wantRefused(t, code, body, "the operator cannot change while any is")
	if code, body := f.post(t, f.s.handleTreeEnable, "/", map[string]any{"asset": f.asset.ID, "operator": treeOperator}, nil); code != 200 {
		t.Fatalf("the same operator again: %d %s", code, body)
	}
}
