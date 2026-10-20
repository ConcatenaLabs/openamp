package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/ConcatenaLabs/openamp/openampd/internal/elements"
	"github.com/ConcatenaLabs/openamp/openampd/internal/rpc"
	"github.com/ConcatenaLabs/openamp/openampd/internal/store"
)

// The supply cap end to end against a node is e2e/supply_cap.py; these tests
// pin what this server does around the token-covenants tool, with a fake tool
// that derives a deterministic script per (instance, count) and builds a
// structurally real mint transaction.

const (
	testColdKey     = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
	testOperatorKey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)

type fakeCapTool struct {
	calls    [][]string
	requests []map[string]any
	failWith string // when set, `build` fails with this message
}

func flagOf(args []string, name string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--"+name {
			return args[i+1]
		}
	}
	return ""
}

// fakeCapSpk is the fake's covenant script for an instance's parameters and a count.
func fakeCapSpk(params map[string]string, minted uint64) string {
	h := sha256.Sum256([]byte(params["ASSET"] + params["OPERATOR_KEY"] + params["COLD_KEY"] + params["CAP"] + strconv.FormatUint(minted, 10)))
	return "5120" + hex.EncodeToString(h[:])
}

// fakeVerifierTokenSpk is the fake's verifier-token script for an instance's
// parameters and the verifier it records.
func fakeVerifierTokenSpk(params map[string]string, verifier string) string {
	h := sha256.Sum256([]byte("vt" + params["VERIFIER_ASSET"] + params["TOKEN"] + params["ISSUER_KEY"] + verifier))
	return "5120" + hex.EncodeToString(h[:])
}

func readInstanceParams(path string) map[string]string {
	b, _ := os.ReadFile(path)
	var inst struct {
		Params map[string]string `json:"params"`
	}
	_ = json.Unmarshal(b, &inst)
	return inst.Params
}

func (f *fakeCapTool) Run(args []string, stdin []byte) ([]byte, error) {
	f.calls = append(f.calls, args)
	var req map[string]any
	if len(stdin) > 0 {
		_ = json.Unmarshal(stdin, &req)
	}
	f.requests = append(f.requests, req)
	switch strings.Join(args[:2], " ") {
	case "supply-cap instance":
		cap, _ := strconv.ParseUint(flagOf(args, "cap"), 10, 64)
		out := map[string]any{
			"instance": 2, "template_hash": "f93a2bffc93db5280ef17f6dc09e99fdee5e4253ccc152afdbebe135265b900d",
			"params": map[string]string{"ASSET": flagOf(args, "asset"), "TOKEN": flagOf(args, "token"),
				"OPERATOR_KEY": flagOf(args, "operator-key"), "COLD_KEY": flagOf(args, "cold-key"),
				"CAP": fmt.Sprintf("%016x", cap)},
			"slots":   map[string]string{"MINTED": "0000000000000000"},
			"genesis": flagOf(args, "genesis"),
			"address": map[string]string{"elementsregtest": "ert1pfakeinstance"},
		}
		return json.Marshal(out)
	case "supply-cap address":
		m, _ := strconv.ParseUint(flagOf(args, "minted"), 10, 64)
		return json.Marshal(map[string]any{
			"script_pubkey": fakeCapSpk(readInstanceParams(flagOf(args, "instance")), m),
			"address":       map[string]string{"elementsregtest": fmt.Sprintf("ert1pfake%d", m)},
		})
	case "supply-cap build":
		if f.failWith != "" {
			return nil, fmt.Errorf("%s", f.failWith)
		}
		params := readInstanceParams(flagOf(args, "instance"))
		minted, _ := strconv.ParseUint(req["minted"].(string), 10, 64)
		amount, _ := strconv.ParseUint(req["amount"].(string), 10, 64)
		coin := req["coin"].(map[string]any)
		prev, err := elements.DeserializeTx(mustHexBytes(coin["tx"].(string)))
		if err != nil {
			return nil, err
		}
		fee := req["fee"].(map[string]any)
		feeCoin := fee["coins"].([]any)[0].(map[string]any)
		feePrev, err := elements.DeserializeTx(mustHexBytes(feeCoin["tx"].(string)))
		if err != nil {
			return nil, err
		}
		tx := &elements.Tx{Version: 2}
		tx.In = append(tx.In,
			&elements.TxIn{Prevout: elements.OutPoint{Hash: internalHash(prev.TxID()), N: uint32(coin["vout"].(float64))}},
			&elements.TxIn{Prevout: elements.OutPoint{Hash: internalHash(feePrev.TxID()), N: uint32(feeCoin["vout"].(float64))}})
		next := fakeCapSpk(params, minted+amount)
		var assetInternal [32]byte
		copy(assetInternal[:], mustHexBytes(params["ASSET"]))
		tx.Out = append(tx.Out,
			&elements.TxOut{Asset: elements.ExplicitAsset(elements.MustHex32(params["TOKEN"])), Value: elements.ExplicitValue(1_0000_0000),
				Nonce: elements.NullNonce(), ScriptPubKey: mustHexBytes(next)},
			&elements.TxOut{Asset: elements.ExplicitAsset(elements.MustHex32(params["ASSET"])), Value: elements.ExplicitValue(amount),
				Nonce: elements.NullNonce(), ScriptPubKey: mustHexBytes(req["mint_to"].(string))})
		tx.NormalizeWitness()
		return json.Marshal(map[string]any{
			"txid": tx.TxID(), "hex": hex.EncodeToString(tx.Serialize()),
			"next_minted": strconv.FormatUint(minted+amount, 10),
			"successor":   map[string]any{"vout": 0, "script_pubkey": next, "address": map[string]string{"elementsregtest": "ert1pnext"}},
		})
	case "verifier-token instance":
		amount, _ := strconv.ParseUint(flagOf(args, "amount"), 10, 64)
		out := map[string]any{
			"instance": 2, "template_hash": "bdcea3847f1b481084f7ef3c7bf8ac3a4d7820a88c2d38393e0bbb0f20b34650",
			"params": map[string]string{"VERIFIER_ASSET": flagOf(args, "verifier-asset"), "TOKEN": flagOf(args, "token"),
				"AMOUNT": fmt.Sprintf("%016x", amount), "ISSUER_KEY": flagOf(args, "issuer-key")},
			"slots":                  map[string]string{"VERIFIER": "ff"},
			"genesis":                flagOf(args, "genesis"),
			"address":                map[string]string{"elementsregtest": "ert1pfakevt"},
			"verifier_script_pubkey": flagOf(args, "verifier"),
		}
		return json.Marshal(out)
	case "verifier-token address":
		return json.Marshal(map[string]any{
			"script_pubkey": fakeVerifierTokenSpk(readInstanceParams(flagOf(args, "instance")), flagOf(args, "verifier")),
			"address":       map[string]string{"elementsregtest": "ert1pfakevt"},
		})
	case "supply-cap follow":
		inst := map[string]any{"instance": 2, "params": map[string]string{"OPERATOR_KEY": req["new_operator_key"].(string),
			"COLD_KEY": req["new_cold_key"].(string)}}
		return json.Marshal(map[string]any{"path": "rekey", "next_instance": inst})
	}
	return nil, fmt.Errorf("fake tool: unexpected %v", args)
}

// withFakeCapTool configures supply caps on s with the fake tool.
func withFakeCapTool(s *Server) *fakeCapTool {
	f := &fakeCapTool{}
	s.tool = f
	s.capOperatorKey = testOperatorKey
	s.capOperatorKeyFile = "/nonexistent/cap-operator.key"
	s.cfg.CapColdKey = testColdKey
	return f
}

// capAsset gives the oa4 fixture's asset a supply cap holding `minted` of
// `cap`, its coin registered with the fake node.
func capAsset(t *testing.T, f *oa4Fixture, cap, minted uint64) *store.SupplyCap {
	t.Helper()
	params := map[string]string{"ASSET": f.asset.ID, "TOKEN": strings.Repeat("44", 32),
		"OPERATOR_KEY": testOperatorKey, "COLD_KEY": testColdKey, "CAP": fmt.Sprintf("%016x", cap)}
	inst, _ := json.Marshal(map[string]any{"instance": 2, "params": params})
	spk := fakeCapSpk(params, minted)
	prev := &elements.Tx{Version: 2}
	prev.Out = append(prev.Out, &elements.TxOut{Asset: elements.ExplicitAsset(elements.MustHex32(params["TOKEN"])),
		Value: elements.ExplicitValue(1_0000_0000), Nonce: elements.NullNonce(), ScriptPubKey: mustHexBytes(spk)})
	prev.NormalizeWitness()
	f.node.rawTxs[prev.TxID()] = hex.EncodeToString(prev.Serialize())
	c := &store.SupplyCap{Instance: inst, Cap: cap, Minted: minted, OperatorKey: testOperatorKey, ColdKey: testColdKey,
		CoinTxid: prev.TxID(), CoinVout: 0, ScriptPubKey: spk, TokenAtoms: 1_0000_0000, IssuedTokenAtoms: 1_0000_0000}
	if err := f.st.Update(func(s *store.State) error {
		a := s.Assets[f.asset.ID]
		a.Entropy = strings.Repeat("33", 32)
		a.Token = params["TOKEN"]
		a.SupplyCap = c
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return c
}

func storedCap(t *testing.T, st *store.Store, id string) *store.SupplyCap {
	t.Helper()
	var c *store.SupplyCap
	st.View(func(s *store.State) {
		if a := s.Assets[id]; a != nil && a.SupplyCap != nil {
			cp := *a.SupplyCap
			c = &cp
		}
	})
	return c
}

// TestSupplyCap_IssuanceTokenGoesToTheCovenant: a hosted issuance pays the
// reissuance token straight to its supply cap with nothing minted, explicitly,
// and records the covenant; the server wallet receives no token.
func TestSupplyCap_IssuanceTokenGoesToTheCovenant(t *testing.T) {
	s, st, node := newIssueServer(t)
	tool := withFakeCapTool(s)
	holder, issuer := regUser(t, st, nil), regUser(t, st, nil)
	code, out, body := callIssue(t, s, map[string]any{
		"name": "Capped", "ticker": "CAPD", "atoms": 1000, "holder_aid": holder.AID, "issuer_aid": issuer.AID,
		"supply_cap": 5000,
	})
	if code != 200 {
		t.Fatalf("issue failed: %d %s", code, body)
	}
	c := storedCap(t, st, out["asset"].(string))
	if c == nil || c.Cap != 5000 || c.Minted != 0 || c.ColdKey != testColdKey || c.OperatorKey != testOperatorKey {
		t.Fatalf("supply cap not recorded as asked: %+v", c)
	}
	sent, err := elements.DeserializeTx(mustHexBytes(node.lastBroadcast))
	if err != nil {
		t.Fatal(err)
	}
	tok := sent.Out[1]
	if hex.EncodeToString(tok.ScriptPubKey) != c.ScriptPubKey {
		t.Fatalf("token output pays %x, not the supply cap %s", tok.ScriptPubKey, c.ScriptPubKey)
	}
	if len(tok.Nonce) != 1 || tok.Nonce[0] != 0 {
		t.Fatalf("token output must be explicit with no nonce, got %x", tok.Nonce)
	}
	if hex.EncodeToString(tok.ScriptPubKey) == node.defaultSpk {
		t.Fatal("the token went to the server wallet")
	}
	if c.CoinTxid != node.broadcast || c.CoinVout != 1 {
		t.Fatalf("covenant coin = %s:%d", c.CoinTxid, c.CoinVout)
	}
	if got := flagOf(tool.calls[0], "cap"); got != "5000" {
		t.Fatalf("instance made with cap %q", got)
	}
	if v := out["supply_cap"].(map[string]any); v["room_atoms"].(float64) != 5000 {
		t.Fatalf("issuance reply shows %v", v)
	}
}

// TestSupplyCap_IssuanceRefusedWithoutACovenant: no tool, or no cold key, is a
// refusal before anything is generated or persisted.
func TestSupplyCap_IssuanceRefusedWithoutACovenant(t *testing.T) {
	s, st, node := newIssueServer(t)
	s.tool = nil
	holder, issuer := regUser(t, st, nil), regUser(t, st, nil)
	body := map[string]any{"name": "N", "ticker": "NOCAP", "atoms": 10, "holder_aid": holder.AID, "issuer_aid": issuer.AID}
	code, out, _ := callIssue(t, s, body)
	if code != 501 || out["error"] != supplyCapNotConfigured {
		t.Fatalf("no tool: want 501 %q, got %d %v", supplyCapNotConfigured, code, out)
	}
	withFakeCapTool(s)
	s.cfg.CapColdKey = ""
	if code, out, _ = callIssue(t, s, body); code != 400 || !strings.Contains(out["error"].(string), "cap_cold_key is required") {
		t.Fatalf("no cold key: got %d %v", code, out)
	}
	body["cap_cold_key"] = testOperatorKey
	if code, out, _ = callIssue(t, s, body); code != 400 || !strings.Contains(out["error"].(string), "operator key") {
		t.Fatalf("cold key = operator key: got %d %v", code, out)
	}
	if node.sends != 0 {
		t.Fatal("a refused issuance broadcast")
	}
	st.View(func(state *store.State) {
		if len(state.Assets) != 0 {
			t.Fatal("a refused issuance persisted an asset")
		}
	})
}

// TestSupplyCap_ConfidentialIssuanceKeepsTheTokenExplicit: blinding an
// issuance blinds the holder's output and the fee change, never the token.
func TestSupplyCap_ConfidentialIssuanceKeepsTheTokenExplicit(t *testing.T) {
	s, st, node := newIssueServer(t)
	withFakeCapTool(s)
	holder, issuer := regUser(t, st, nil), regUser(t, st, nil)
	code, out, body := callIssue(t, s, map[string]any{
		"name": "C", "ticker": "CONF", "atoms": 10, "holder_aid": holder.AID, "issuer_aid": issuer.AID, "confidential": true,
	})
	if code != 200 {
		t.Fatalf("issue failed: %d %s", code, body)
	}
	sent, _ := elements.DeserializeTx(mustHexBytes(node.lastBroadcast))
	c := storedCap(t, st, out["asset"].(string))
	if hex.EncodeToString(sent.Out[1].ScriptPubKey) != c.ScriptPubKey || len(sent.Out[1].Nonce) != 1 {
		t.Fatalf("token output must pay the supply cap explicitly: %x nonce %x", sent.Out[1].ScriptPubKey, sent.Out[1].Nonce)
	}
	if !isBlindingNonce(sent.Out[0].Nonce) || !isBlindingNonce(sent.Out[2].Nonce) {
		t.Fatal("holder output and fee change must carry blinding nonces")
	}
}

// TestSupplyCap_MintGoesThroughTheTool: a reissue hands the tool the covenant
// coin, the count, the amount, the target enclave and an explicit fee coin of
// the server's fee asset; the wallet signs; the covenant's next coin and count
// are recorded and shown with the supply.
func TestSupplyCap_MintGoesThroughTheTool(t *testing.T) {
	f := newOA4Fixture(t)
	tool := withFakeCapTool(f.s)
	before := capAsset(t, f, 10_000, 1_000).ScriptPubKey
	code, body := callReissue(t, f.s, map[string]any{
		"asset": f.asset.ID, "target_aid": f.investor.AID, "atoms": 2_500, "request_id": "cap-1",
	})
	if code != 200 {
		t.Fatalf("mint failed: %d %s", code, body)
	}
	req := tool.requests[len(tool.requests)-1]
	call := tool.calls[len(tool.calls)-1]
	if call[0] != "supply-cap" || call[1] != "build" || flagOf(call, "key-file") != f.s.capOperatorKeyFile {
		t.Fatalf("tool called as %v", call)
	}
	investorTree, _ := f.s.treeFor(f.investor, f.asset)
	if req["path"] != "mint" || req["minted"] != "1000" || req["amount"] != "2500" ||
		req["mint_to"] != hex.EncodeToString(investorTree.ScriptPubKey()) || req["entropy"] != strings.Repeat("33", 32) {
		t.Fatalf("tool request: %v", req)
	}
	fee := req["fee"].(map[string]any)
	if fee["atoms"] != "100" || fee["change_to"] != oa4ChgSpk {
		t.Fatalf("fee: %v", fee)
	}
	sent, err := elements.DeserializeTx(mustHexBytes(f.node.lastBroadcast))
	if err != nil {
		t.Fatal(err)
	}
	after := storedCap(t, f.st, f.asset.ID)
	if after.Minted != 3_500 || after.CoinTxid != sent.TxID() || after.CoinVout != 0 || after.ScriptPubKey == before {
		t.Fatalf("next coin not recorded: %+v", after)
	}
	if _, ok := f.st.GetPendingReissue("cap-1"); ok {
		t.Fatal("reservation left behind")
	}
	_, out := callSupply(t, f.s, f.asset.ID)
	v := out["supply_cap"].(map[string]any)
	if v["minted_atoms"].(float64) != 3_500 || v["room_atoms"].(float64) != 6_500 || v["holds_the_whole_token"] != true {
		t.Fatalf("supply shows %v", v)
	}
}

// TestSupplyCap_MintRefusals: over the cap, confidential, a coin spent by
// another path, no covenant, another operator key: each refused before the
// tool builds anything.
func TestSupplyCap_MintRefusals(t *testing.T) {
	f := newOA4Fixture(t)
	tool := withFakeCapTool(f.s)
	capAsset(t, f, 10_000, 9_000)
	mint := func(atoms int, extra map[string]any) (int, string) {
		body := map[string]any{"asset": f.asset.ID, "target_aid": f.investor.AID, "atoms": atoms,
			"request_id": fmt.Sprintf("r-%d-%d", atoms, len(tool.calls))}
		for k, v := range extra {
			body[k] = v
		}
		return callReissue(t, f.s, body)
	}
	if code, body := mint(1_001, nil); code != 409 || !strings.Contains(body, "above its cap of 10000 (9000 minted, 1000 left)") {
		t.Fatalf("over the cap: %d %s", code, body)
	}
	if code, body := mint(10, map[string]any{"confidential": true}); code != 400 || !strings.Contains(body, "cannot be confidential") {
		t.Fatalf("confidential: %d %s", code, body)
	}
	if err := f.st.Update(func(s *store.State) error {
		s.Assets[f.asset.ID].SupplyCap.OperatorKey = testColdKey
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if code, body := mint(10, nil); code != 409 || !strings.Contains(body, "not this server's") {
		t.Fatalf("other operator key: %d %s", code, body)
	}
	if err := f.st.Update(func(s *store.State) error {
		s.Assets[f.asset.ID].SupplyCap = nil
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if code, body := mint(10, nil); code != 409 || !strings.Contains(body, "in no supply cap") {
		t.Fatalf("no covenant: %d %s", code, body)
	}
	for _, c := range tool.calls {
		if c[1] == "build" {
			t.Fatalf("the tool built a refused mint: %v", c)
		}
	}
	if f.node.sends != 0 {
		t.Fatal("a refused mint was broadcast")
	}
}

// TestSupplyCap_CrashRetryRecordsTheNextCoin: a mint reserved and broadcast
// before a crash is replayed identically, and the retry also records the
// covenant's next coin, so the following mint spends the right one.
func TestSupplyCap_CrashRetryRecordsTheNextCoin(t *testing.T) {
	f := newOA4Fixture(t)
	withFakeCapTool(f.s)
	capAsset(t, f, 10_000, 0)
	if err := f.st.ReservePendingReissue("crash-1", store.PendingReissue{
		SignedHex: "00", Txid: "reservedtxid", Asset: f.asset.ID,
		NextMinted: 700, NextScriptPubKey: "5120" + strings.Repeat("99", 32), NextAddress: "ert1pnext",
	}); err != nil {
		t.Fatal(err)
	}
	code, body := callReissue(t, f.s, map[string]any{
		"asset": f.asset.ID, "target_aid": f.investor.AID, "atoms": 700, "request_id": "crash-1",
	})
	if code != 200 || !strings.Contains(body, "reservedtxid") {
		t.Fatalf("retry: %d %s", code, body)
	}
	c := storedCap(t, f.st, f.asset.ID)
	if c.CoinTxid != "reservedtxid" || c.Minted != 700 || c.Address != "ert1pnext" {
		t.Fatalf("next coin not recorded on retry: %+v", c)
	}
}

// TestSupplyCap_MoveAnIssuedToken: an asset issued before supply caps has its
// token moved from the wallet into one, whole and explicit; asking again
// answers with the covenant.
func TestSupplyCap_MoveAnIssuedToken(t *testing.T) {
	f := newOA4Fixture(t)
	withFakeCapTool(f.s)
	token := strings.Repeat("44", 32)
	if err := f.st.Update(func(s *store.State) error {
		a := s.Assets[f.asset.ID]
		a.Entropy, a.Token = strings.Repeat("33", 32), token
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	f.node.confUnspent = append(f.node.confUnspent, rpc.ConfUnspent{
		TxID: strings.Repeat("aa", 32), Vout: 1, ScriptPubKey: "0014" + strings.Repeat("dd", 20),
		Amount: 1.0, Asset: token, Spendable: true,
	})
	code, out := postJSON(t, f.s.handleSupplyCapMove, "/v1/issuer/supply-cap", map[string]any{"asset": f.asset.ID, "cap": 42})
	if code != 200 || out["status"] != "moved" {
		t.Fatalf("move: %d %v", code, out)
	}
	sent, _ := elements.DeserializeTx(mustHexBytes(f.node.lastBroadcast))
	c := storedCap(t, f.st, f.asset.ID)
	if hex.EncodeToString(sent.Out[0].ScriptPubKey) != c.ScriptPubKey || len(sent.Out[0].Nonce) != 1 {
		t.Fatalf("the token output does not pay the supply cap explicitly: %x", sent.Out[0].ScriptPubKey)
	}
	if amt, _ := elements.ExplicitValueAmount(sent.Out[0].Value); amt != 1_0000_0000 || c.TokenAtoms != amt || c.Cap != 42 {
		t.Fatalf("moved %d, recorded %+v", amt, c)
	}
	if f.node.blindCalled {
		t.Fatal("an explicit token coin needs no blinding")
	}
	code, out = postJSON(t, f.s.handleSupplyCapMove, "/v1/issuer/supply-cap", map[string]any{"asset": f.asset.ID, "cap": 42})
	if code != 200 || out["status"] != "already in its supply cap" || f.node.sends != 1 {
		t.Fatalf("second move: %d %v (sends %d)", code, out, f.node.sends)
	}
}

// TestSupplyCap_RekeyIsRecorded: a rekey made off this server is recorded once
// the tool follows the spend into the instance under the keys named.
func TestSupplyCap_RekeyIsRecorded(t *testing.T) {
	f := newOA4Fixture(t)
	withFakeCapTool(f.s)
	capAsset(t, f, 10_000, 100)
	spend := &elements.Tx{Version: 2}
	spend.Out = append(spend.Out, &elements.TxOut{Asset: elements.ExplicitAsset(elements.MustHex32(oa4FeeID)),
		Value: elements.ExplicitValue(1), Nonce: elements.NullNonce(), ScriptPubKey: mustHexBytes(oa4ChgSpk)})
	spend.NormalizeWitness()
	f.node.rawTxs[spend.TxID()] = hex.EncodeToString(spend.Serialize())
	newOp := strings.Repeat("0", 63) + "1"
	code, out := postJSON(t, f.s.handleSupplyCapRekey, "/v1/issuer/supply-cap/rekey", map[string]any{
		"asset": f.asset.ID, "txid": spend.TxID(), "new_operator_key": newOp, "new_cold_key": testColdKey,
	})
	if code != 200 || out["status"] != "rekeyed" || out["note"] == nil {
		t.Fatalf("rekey: %d %v", code, out)
	}
	c := storedCap(t, f.st, f.asset.ID)
	if c.OperatorKey != newOp || c.CoinTxid != spend.TxID() || c.Minted != 100 {
		t.Fatalf("rekey not recorded: %+v", c)
	}
}
