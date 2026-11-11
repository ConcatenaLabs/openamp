package server

import (
	"encoding/hex"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ConcatenaLabs/openamp/openampd/internal/elements"
	"github.com/ConcatenaLabs/openamp/openampd/internal/store"
)

var testFill = []byte{0x51} // any covenant: openampd judges the transaction, not the price

func (f *htlcFixture) orderSpk(t *testing.T, maker *store.User, expiry uint32) []byte {
	t.Helper()
	tree, err := f.s.orderTree(f.asset, maker, testFill, expiry)
	if err != nil {
		t.Fatal(err)
	}
	return tree.ScriptPubKey()
}

// Placement: the order its terms describe, the maker's own coin.
func TestGatedOrderPlacement(t *testing.T) {
	f := newHTLCFixture(t, store.Rules{})
	expiry := uint32(f.now.Add(24 * time.Hour).Unix())
	tx := &elements.Tx{Version: 2, Out: []*elements.TxOut{f.out(f.orderSpk(t, f.seller, expiry), 500)}}
	req := []orderOutput{{Output: 0, Fill: hex.EncodeToString(testFill), Expiry: expiry}}
	admitted, recs, err := f.s.admitOrderOutputs(tx, f.asset, f.seller, req)
	if err != nil || len(recs) != 1 || admitted[recs[0].SPK].AID != f.seller.AID {
		t.Fatalf("placement: %v %+v", err, recs)
	}
	atoms := map[string]uint64{}
	if err := f.s.checkTransferAdmitting(tx, f.asset, f.seller, atoms, admitted); err != nil || len(atoms) != 0 {
		t.Fatalf("placement judged as a transfer: %v %v", err, atoms)
	}
	for _, edit := range map[string]func(r []orderOutput){
		"another fill":          func(r []orderOutput) { r[0].Fill = "52" },
		"another expiry":        func(r []orderOutput) { r[0].Expiry++ },
		"a height expiry":       func(r []orderOutput) { r[0].Expiry = 800_000 },
		"too soon":              func(r []orderOutput) { r[0].Expiry = uint32(f.now.Add(30 * time.Minute).Unix()) },
		"too far":               func(r []orderOutput) { r[0].Expiry = uint32(f.now.Add(31 * 24 * time.Hour).Unix()) },
		"no fill":               func(r []orderOutput) { r[0].Fill = "" },
		"output out of range":   func(r []orderOutput) { r[0].Output = 2 },
		"a fill that isn't hex": func(r []orderOutput) { r[0].Fill = "zz" },
	} {
		r := []orderOutput{req[0]}
		edit(r)
		_, _, err := f.s.admitOrderOutputs(tx, f.asset, f.seller, r)
		wantRefusal(t, err, "order")
	}
}

// A fill: only with the broadcast, only the maker's order, never at or after
// the expiry, and judged by every rule with the maker as sender.
func TestGatedOrderFill(t *testing.T) {
	f := newHTLCFixture(t, store.Rules{AllowedCategories: []string{"kyc:eu"}})
	f.s.signer = stubPolicySigner{}
	expiry := uint32(f.now.Add(24 * time.Hour).Unix())
	orderSpk := f.orderSpk(t, f.seller, expiry)
	rec := &store.GatedOrder{SPK: hex.EncodeToString(orderSpk), Asset: f.asset.ID, MakerAID: f.seller.AID,
		Fill: hex.EncodeToString(testFill), Expiry: expiry}
	if err := f.st.Update(func(x *store.State) error { x.GatedOrders[rec.SPK] = rec; return nil }); err != nil {
		t.Fatal(err)
	}
	buyerSpk, _ := hex.DecodeString(enclaveSpk(t, f.s, f.buyer, f.asset))
	spent := []*elements.SpentOutput{
		{Asset: elements.ExplicitAsset(elements.MustHex32(f.asset.ID)), Value: elements.ExplicitValue(500), ScriptPubKey: orderSpk},
		{Asset: elements.ExplicitAsset(elements.MustHex32(strings.Repeat("44", 32))), Value: elements.ExplicitValue(9000), ScriptPubKey: []byte{0x51}},
	}
	fillTx := func(to []byte) *elements.Tx {
		return &elements.Tx{Version: 2, In: []*elements.TxIn{{}, {}}, Out: []*elements.TxOut{
			f.out(to, 100), f.out(orderSpk, 400)}}
	}
	call := func(tx *elements.Tx, sender *store.User, dry, broadcast bool) (int, string) {
		w := httptest.NewRecorder()
		f.s.handleOrderFill(w, tx, spent, f.asset, sender, []orderInput{{Input: 0}}, dry, broadcast)
		return w.Code, w.Body.String()
	}
	if code, body := call(fillTx(buyerSpk), f.seller, true, false); code != 200 || !strings.Contains(body, `"atoms":100`) {
		t.Fatalf("a dry fill: %d %s", code, body)
	}
	if code, _ := call(fillTx(buyerSpk), f.seller, false, false); code != 400 {
		t.Fatalf("a fill without the broadcast: %d", code)
	}
	if code, body := call(fillTx(buyerSpk), f.buyer, true, false); code != 403 || !strings.Contains(body, "not the sender's order") {
		t.Fatalf("someone else's order: %d %s", code, body)
	}
	noCat := regUser(t, f.st, nil)
	noCatSpk, _ := hex.DecodeString(enclaveSpk(t, f.s, noCat, f.asset))
	if code, body := call(fillTx(noCatSpk), f.seller, true, false); code != 403 || !strings.Contains(body, "category") {
		t.Fatalf("a buyer without the category: %d %s", code, body)
	}
	f.now = time.Unix(int64(expiry), 0)
	if code, body := call(fillTx(buyerSpk), f.seller, true, false); code != 403 || !strings.Contains(body, "expired") {
		t.Fatalf("a fill at the expiry: %d %s", code, body)
	}
}
