package elements

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type htlcVec struct {
	Hash          string `json:"hash"`
	BuyerX        string `json:"buyer_x"`
	PolicyX       string `json:"policy_x"`
	IssuerX       string `json:"issuer_x"`
	TSeq          uint32 `json:"t_seq"`
	SellerVersion byte   `json:"seller_version"`
	SellerProgram string `json:"seller_program"`
	Asset         string `json:"asset"`
	FeeAsset      string `json:"fee_asset"`
	Value         uint64 `json:"value"`
	Spk           string `json:"spk"`
	ClaimScript   string `json:"claim_script"`
	ClaimControl  string `json:"claim_control"`
	RefundScript  string `json:"refund_script"`
	RefundControl string `json:"refund_control"`
	ClawScript    string `json:"claw_script"`
	ClawControl   string `json:"claw_control"`
}

func loadHTLCVectors(t *testing.T) map[string]htlcVec {
	t.Helper()
	b, err := os.ReadFile("testdata/htlc_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]htlcVec
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func checkTree(t *testing.T, name string, tree *TapTree, v htlcVec, leaves map[string][2]string) {
	t.Helper()
	if got := hex.EncodeToString(tree.ScriptPubKey()); got != v.Spk {
		t.Errorf("%s spk = %s want %s", name, got, v.Spk)
	}
	if len(tree.Leaves) != len(leaves) {
		t.Errorf("%s: %d leaves, want %d", name, len(tree.Leaves), len(leaves))
	}
	for leaf, want := range leaves {
		if got := hex.EncodeToString(tree.Leaves[leaf].Script); got != want[0] {
			t.Errorf("%s %s script = %s want %s", name, leaf, got, want[0])
		}
		cb, err := tree.ControlBlock(leaf)
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(cb); got != want[1] {
			t.Errorf("%s %s control = %s want %s", name, leaf, got, want[1])
		}
	}
}

// The HTLC and the pot match the test framework's construction byte for
// byte, three leaves included.
func TestSwapHTLCVectors(t *testing.T) {
	vs := loadHTLCVectors(t)
	for _, name := range []string{"htlc_claw", "htlc_noclaw"} {
		v := vs[name]
		terms := SwapHTLCTerms{
			Hash: hb32(t, v.Hash), BuyerX: hb32(t, v.BuyerX), PolicyX: hb32(t, v.PolicyX),
			TSeq: v.TSeq, SellerProgram: hb32(t, v.SellerProgram), Asset: hb32(t, v.Asset), Value: v.Value,
		}
		leaves := map[string][2]string{"claim": {v.ClaimScript, v.ClaimControl}, "refund": {v.RefundScript, v.RefundControl}}
		if v.IssuerX != "" {
			x := hb32(t, v.IssuerX)
			terms.IssuerX = &x
			leaves["claw"] = [2]string{v.ClawScript, v.ClawControl}
		}
		tree, err := SwapHTLCTree(terms)
		if err != nil {
			t.Fatal(err)
		}
		checkTree(t, name, tree, v, leaves)
	}
	for _, name := range []string{"pot_v0", "pot_v1"} {
		v := vs[name]
		prog, _ := hex.DecodeString(v.SellerProgram)
		tree, err := FeePotTree(FeePotTerms{
			Hash: hb32(t, v.Hash), BuyerX: hb32(t, v.BuyerX), TSeq: v.TSeq,
			SellerVersion: v.SellerVersion, SellerProgram: prog, FeeAsset: hb32(t, v.FeeAsset), Value: v.Value,
		})
		if err != nil {
			t.Fatal(err)
		}
		checkTree(t, name, tree, v, map[string][2]string{"claim": {v.ClaimScript, v.ClaimControl}, "refund": {v.RefundScript, v.RefundControl}})
	}
}

// Every lock is a time: a height, zero atoms or a bad payout is refused.
func TestSwapHTLCRefusals(t *testing.T) {
	base := SwapHTLCTerms{TSeq: MinTimeLock, Value: 1}
	if _, err := SwapHTLCTree(base); err != nil {
		t.Fatalf("a time lock and one atom are fine: %v", err)
	}
	h := base
	h.TSeq = MinTimeLock - 1
	if _, err := SwapHTLCTree(h); err == nil {
		t.Fatal("a height T_seq was accepted")
	}
	z := base
	z.Value = 0
	if _, err := SwapHTLCTree(z); err == nil {
		t.Fatal("an empty HTLC was accepted")
	}
	pot := FeePotTerms{TSeq: MinTimeLock, SellerVersion: 0, SellerProgram: make([]byte, 20), Value: 1}
	if _, err := FeePotTree(pot); err != nil {
		t.Fatalf("a v0 payout: %v", err)
	}
	for _, bad := range []FeePotTerms{
		{TSeq: MinTimeLock - 1, SellerVersion: 0, SellerProgram: make([]byte, 20), Value: 1},
		{TSeq: MinTimeLock, SellerVersion: 1, SellerProgram: make([]byte, 20), Value: 1},
		{TSeq: MinTimeLock, SellerVersion: 2, SellerProgram: make([]byte, 32), Value: 1},
		{TSeq: MinTimeLock, SellerVersion: 0, SellerProgram: make([]byte, 20), Value: 0},
	} {
		if _, err := FeePotTree(bad); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
}

// Three and four leaves split as the test framework splits them.
func TestBuildTreeShapes(t *testing.T) {
	a, b, c := []byte{0x51}, []byte{0x52}, []byte{0x53}
	tree, err := BuildTree(NUMS, Leaf{"a", a}, Leaf{"b", b}, Leaf{"c", c})
	if err != nil {
		t.Fatal(err)
	}
	ha, hb, hc := TapLeafHash(a), TapLeafHash(b), TapLeafHash(c)
	bc := TapBranchHash(hb, hc)
	if tree.Root != TapBranchHash(ha, bc) {
		t.Fatal("three leaves are not [a, [b, c]]")
	}
	if hex.EncodeToString(tree.Leaves["a"].MerkleBranch) != hex.EncodeToString(bc[:]) ||
		hex.EncodeToString(tree.Leaves["b"].MerkleBranch) != hex.EncodeToString(append(hc[:], ha[:]...)) {
		t.Fatal("branches run leaf to root")
	}
	if _, err := BuildTree(NUMS, Leaf{"a", a}, Leaf{"a", b}); err == nil {
		t.Fatal("two leaves of one name were accepted")
	}
}
