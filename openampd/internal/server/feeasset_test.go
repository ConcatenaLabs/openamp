package server

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ConcatenaLabs/openamp/openampd/internal/rpc"
	"github.com/ConcatenaLabs/openamp/openampd/internal/store"
)

const (
	feeTestA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	feeTestB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	feeTestR = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
)

func feeTestCoin(txid, asset string, atoms uint64) rpc.Unspent {
	return rpc.Unspent{TxID: txid, Vout: 0, Amount: float64(atoms) / 1e8, Asset: asset, Spendable: true}
}

func TestFeeAtomsAt_KeepsTheFeesValue(t *testing.T) {
	for _, c := range []struct{ value, rate, want uint64 }{
		{1000, 100000000, 1000}, // rated 1:1 with the reference unit
		{1000, 5000000000, 20},  // worth 50 reference units a coin: fewer atoms
		{100, 3000000000, 4},    // 3.33.. rounds up, never under the value
		{1000, 1000000, 100000}, // worth 0.01 a coin: more atoms
	} {
		got, ok := feeAtomsAt(c.value, c.rate)
		if !ok || got != c.want {
			t.Fatalf("feeAtomsAt(%d, %d) = %d, %v; want %d", c.value, c.rate, got, ok, c.want)
		}
	}
	if _, ok := feeAtomsAt(1000, 0); ok {
		t.Fatal("an unrated asset has no fee")
	}
}

// With no -feeasset, the fee follows the wallet rule: the asset whose largest
// coin is worth most at the node's rates pays, in its own atoms, whatever the
// policy asset is; an asset the server moves never pays, even rated.
func TestFeeUTXO_FollowsTheRule(t *testing.T) {
	s, st, node := newM9Server(t, Config{FeeSats: 100})
	// R is a restricted asset this server issued; the node rates it anyway.
	if err := st.Update(func(x *store.State) error {
		x.Assets[feeTestR] = &store.Asset{ID: feeTestR, Ticker: "RST"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	node.feeRates = map[string]uint64{feeTestA: 100000000, feeTestB: 5000000000, feeTestR: 900000000000}
	node.feeUnspent = []rpc.Unspent{
		feeTestCoin(strings.Repeat("01", 32), feeTestA, 1000000), // worth 1e14
		feeTestCoin(strings.Repeat("02", 32), feeTestB, 50000),   // worth 2.5e14: the rule's choice
		feeTestCoin(strings.Repeat("03", 32), feeTestB, 400),
		feeTestCoin(strings.Repeat("04", 32), feeTestR, 99000000),  // restricted: never a fee
		feeTestCoin(strings.Repeat("05", 32), oa4FeeID, 900000000), // not accepted by this node
	}
	c, err := s.feeUTXO(2)
	if err != nil {
		t.Fatal(err)
	}
	if c.asset != feeTestB || c.txid != strings.Repeat("02", 32) || c.fee != 2 {
		t.Fatalf("picked %+v; want B's 50000-atom coin paying 2 atoms", c)
	}

	// The rule values coins, not atoms: B's coin covers 25,000 fees of 2 atoms,
	// A's only 10,000 of 100, so B still pays when 20,000 fees are asked.
	c, err = s.feeUTXO(20000)
	if err != nil {
		t.Fatal(err)
	}
	if c.asset != feeTestB {
		t.Fatalf("picked %+v; want B", c)
	}

	// Nothing covers: the refusal names what the node accepts, and not R.
	_, err = s.feeUTXO(30000)
	var nf *NoFeeCoin
	if !errors.As(err, &nf) || feeStatus(err) != 503 {
		t.Fatalf("want a NoFeeCoin refusal, got %v", err)
	}
	if !strings.Contains(nf.Reason, feeTestA) || !strings.Contains(nf.Reason, feeTestB) || strings.Contains(nf.Reason, feeTestR) {
		t.Fatalf("refusal names the wrong assets: %s", nf.Reason)
	}
}

// A tie in worth goes to the lower asset id, which says nothing about either.
func TestPickFeeCoins_TieGoesToTheLowerID(t *testing.T) {
	rates := map[string]uint64{feeTestA: 100000000, feeTestB: 100000000}
	got := pickFeeCoins(100, rates, []feeCoin{
		{txid: "b", sats: 5000, asset: feeTestB},
		{txid: "a", sats: 5000, asset: feeTestA},
	})
	if len(got) != 2 || got[0].asset != feeTestA {
		t.Fatalf("got %+v", got)
	}
}

// An operator's -feeasset is the only asset used, and refused once the node no
// longer accepts it, rather than quietly served by another.
func TestFeeUTXO_OperatorsAssetOnly(t *testing.T) {
	s, _, node := newM9Server(t, Config{FeeAsset: feeTestA, FeeSats: 100})
	node.feeRates = map[string]uint64{feeTestA: 100000000, feeTestB: 5000000000}
	node.feeUnspent = []rpc.Unspent{
		feeTestCoin(strings.Repeat("01", 32), feeTestA, 1000),
		feeTestCoin(strings.Repeat("02", 32), feeTestB, 50000),
	}
	c, err := s.feeUTXO(2)
	if err != nil || c.asset != feeTestA || c.fee != 100 {
		t.Fatalf("got %+v, %v; want A paying 100", c, err)
	}
	node.feeRates = map[string]uint64{feeTestB: 5000000000}
	_, err = s.feeUTXO(2)
	var nf *NoFeeCoin
	if !errors.As(err, &nf) || !strings.Contains(nf.Reason, "-feeasset "+feeTestA) {
		t.Fatalf("want the -feeasset refusal, got %v", err)
	}
}

// A node that accepts nothing the server may pay in refuses with a clear line.
func TestFeeUTXO_NodeAcceptsNothing(t *testing.T) {
	s, _, node := newM9Server(t, Config{FeeSats: 100})
	node.feeRates = map[string]uint64{}
	node.feeUnspent = []rpc.Unspent{feeTestCoin(strings.Repeat("01", 32), feeTestA, 1000)}
	_, err := s.feeUTXO(2)
	var nf *NoFeeCoin
	if !errors.As(err, &nf) || !strings.Contains(nf.Reason, "accepts no asset for fees") {
		t.Fatalf("got %v", err)
	}
}

// The node keys a labelled asset by its label; the rule needs its id.
func TestFeeRates_ResolvesLabels(t *testing.T) {
	call := func(out any, method string, params ...any) error {
		switch method {
		case "getfeeexchangerates":
			*(out.(*map[string]json.Number)) = map[string]json.Number{"bitcoin": "100000000", feeTestA: "5000000000", feeTestB: "0"}
		case "dumpassetlabels":
			*(out.(*map[string]string)) = map[string]string{"bitcoin": strings.ToUpper(feeTestR)}
		}
		return nil
	}
	got, err := FeeRates(call)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[feeTestR] != 100000000 || got[feeTestA] != 5000000000 {
		t.Fatalf("got %v", got)
	}
}
