package elements

import (
	"encoding/hex"
	"testing"
)

// The gated order matches the test framework's construction byte for byte,
// with and without clawback.
func TestGatedOrderVectors(t *testing.T) {
	vs := loadHTLCVectors(t)
	for _, name := range []string{"gated_claw", "gated_noclaw"} {
		v := vs[name]
		fill, _ := hex.DecodeString(v.Fill)
		terms := GatedOrderTerms{
			PolicyX: hb32(t, v.PolicyX), Fill: fill, Expiry: v.Expiry,
			MakerProgram: hb32(t, v.MakerProgram), Asset: hb32(t, v.Asset),
		}
		leaves := map[string][2]string{"fill": {v.FillScript, v.FillControl}, "refund": {v.RefundScript, v.RefundControl}}
		if v.IssuerX != "" {
			x := hb32(t, v.IssuerX)
			terms.IssuerX = &x
			leaves["claw"] = [2]string{v.ClawScript, v.ClawControl}
		}
		tree, err := GatedOrderTree(terms)
		if err != nil {
			t.Fatal(err)
		}
		checkTree(t, name, tree, v, leaves)
	}
}

// An expiry is a time, and the wrapped fill is neither empty nor oversized.
func TestGatedOrderRefusals(t *testing.T) {
	base := GatedOrderTerms{Fill: []byte{0x51}, Expiry: MinTimeLock}
	if _, err := GatedOrderTree(base); err != nil {
		t.Fatalf("a time and a fill are fine: %v", err)
	}
	for name, edit := range map[string]func(*GatedOrderTerms){
		"a height expiry": func(g *GatedOrderTerms) { g.Expiry = MinTimeLock - 1 },
		"no fill":         func(g *GatedOrderTerms) { g.Fill = nil },
		"a huge fill":     func(g *GatedOrderTerms) { g.Fill = make([]byte, GatedFillMax+1) },
	} {
		g := base
		edit(&g)
		if _, err := GatedOrderTree(g); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}
