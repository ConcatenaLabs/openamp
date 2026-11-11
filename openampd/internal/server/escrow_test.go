package server

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/ConcatenaLabs/openamp/openampd/internal/elements"
	"github.com/ConcatenaLabs/openamp/openampd/internal/store"
)

type escrowFixture struct {
	s             *Server
	st            *store.Store
	asset         *store.Asset
	seller, buyer *store.User
	other         *store.User
	hash          [32]byte
	now           time.Time
	tSeq          uint32
}

func newEscrowFixture(t *testing.T, rules store.Rules) *escrowFixture {
	t.Helper()
	s, st, _ := newOA3Server(t)
	f := &escrowFixture{s: s, st: st}
	issuer := regUser(t, st, nil)
	f.seller = regUser(t, st, []string{"kyc:eu"})
	f.buyer = regUser(t, st, []string{"kyc:eu"})
	f.other = regUser(t, st, []string{"kyc:eu"})
	f.asset = oa3Asset(t, issuer.AID, rules)
	putAsset(t, st, f.asset)
	f.hash = sha256.Sum256([]byte("the buyer's secret"))
	f.now = time.Unix(1_800_000_000, 0)
	s.clock = func() time.Time { return f.now }
	f.tSeq = uint32(f.now.Add(4 * time.Hour).Unix())
	return f
}

func (f *escrowFixture) escrowSpk(t *testing.T, buyer *store.User, hash [32]byte, tSeq uint32, value uint64) []byte {
	t.Helper()
	tree, err := f.s.escrowTree(f.asset, f.seller, buyer, hash, tSeq, value)
	if err != nil {
		t.Fatal(err)
	}
	return tree.ScriptPubKey()
}

func (f *escrowFixture) out(spk []byte, value uint64) *elements.TxOut {
	return &elements.TxOut{
		Asset: elements.ExplicitAsset(elements.MustHex32(f.asset.ID)), Value: elements.ExplicitValue(value),
		Nonce: elements.NullNonce(), ScriptPubKey: spk,
	}
}

func (f *escrowFixture) lockTx(t *testing.T, value uint64) *elements.Tx {
	return &elements.Tx{Version: 2, Out: []*elements.TxOut{f.out(f.escrowSpk(t, f.buyer, f.hash, f.tSeq, value), value)}}
}

func (f *escrowFixture) req() []escrowOutput {
	return []escrowOutput{{Output: 0, BuyerAID: f.buyer.AID, Hash: hex.EncodeToString(f.hash[:]), TSeq: f.tSeq}}
}

func wantRefusal(t *testing.T, err error, code string) {
	t.Helper()
	pr, ok := err.(*PolicyRefusal)
	if !ok || pr.Code != code {
		t.Fatalf("want refusal %q, got %v (%T)", code, err, err)
	}
}

// The lock: the escrow its terms describe, for a registered buyer who could
// receive it now, admitted as the seller's own coin.
func TestEscrowLockAdmission(t *testing.T) {
	f := newEscrowFixture(t, store.Rules{AllowedCategories: []string{"kyc:eu"}})
	admitted, recs, err := f.s.admitEscrowOutputs(f.lockTx(t, 1000), f.asset, f.seller, f.req())
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Value != 1000 || recs[0].BuyerAID != f.buyer.AID || admitted[recs[0].SPK].AID != f.seller.AID {
		t.Fatalf("admitted %v, records %+v", admitted, recs[0])
	}
	// The escrow is the seller's own coin: the lock moves nothing to anyone.
	atoms := map[string]uint64{}
	if err := f.s.checkTransferAdmitting(f.lockTx(t, 1000), f.asset, f.seller, atoms, admitted); err != nil || len(atoms) != 0 {
		t.Fatalf("lock judged as a transfer: %v %v", err, atoms)
	}

	cases := []struct {
		name string
		edit func(r []escrowOutput, tx *elements.Tx)
		code string
	}{
		{"terms of another hash", func(r []escrowOutput, tx *elements.Tx) { r[0].Hash = strings.Repeat("ab", 32) }, "escrow"},
		{"a height t_seq", func(r []escrowOutput, tx *elements.Tx) { r[0].TSeq = 499_999_999 }, "escrow"},
		{"t_seq too soon", func(r []escrowOutput, tx *elements.Tx) { r[0].TSeq = uint32(f.now.Add(90 * time.Minute).Unix()) }, "escrow"},
		{"t_seq too far", func(r []escrowOutput, tx *elements.Tx) { r[0].TSeq = uint32(f.now.Add(8 * 24 * time.Hour).Unix()) }, "escrow"},
		{"unregistered buyer", func(r []escrowOutput, tx *elements.Tx) { r[0].BuyerAID = strings.Repeat("cd", 20) }, "unregistered"},
		{"the seller as buyer", func(r []escrowOutput, tx *elements.Tx) { r[0].BuyerAID = f.seller.AID }, "escrow"},
		{"output out of range", func(r []escrowOutput, tx *elements.Tx) { r[0].Output = 3 }, "escrow"},
		{"another asset", func(r []escrowOutput, tx *elements.Tx) {
			tx.Out[0].Asset = elements.ExplicitAsset(elements.MustHex32(strings.Repeat("99", 32)))
		}, "escrow"},
	}
	for _, c := range cases {
		r := f.req()
		tx := f.lockTx(t, 1000)
		c.edit(r, tx)
		_, _, err := f.s.admitEscrowOutputs(tx, f.asset, f.seller, r)
		if err == nil {
			t.Fatalf("%s: admitted", c.name)
		}
		wantRefusal(t, err, c.code)
	}

	// A buyer who could not receive the asset now is refused at the lock, so
	// nobody locks a coin no one can claim.
	noCat := regUser(t, f.st, nil)
	r := f.req()
	r[0].BuyerAID = noCat.AID
	tx := &elements.Tx{Version: 2, Out: []*elements.TxOut{f.out(f.escrowSpk(t, noCat, f.hash, f.tSeq, 1000), 1000)}}
	_, _, err = f.s.admitEscrowOutputs(tx, f.asset, f.seller, r)
	wantRefusal(t, err, "category")
	if err := f.st.Update(func(x *store.State) error { x.Users[f.buyer.AID].Frozen = true; return nil }); err != nil {
		t.Fatal(err)
	}
	_, _, err = f.s.admitEscrowOutputs(f.lockTx(t, 1000), f.asset, f.seller, f.req())
	wantRefusal(t, err, "frozen")
}

// The claim: one escrow of the sender's, before the cut-off, its whole amount
// to its buyer's enclave and nowhere else.
func TestEscrowClaim(t *testing.T) {
	f := newEscrowFixture(t, store.Rules{})
	_, recs, err := f.s.admitEscrowOutputs(f.lockTx(t, 1000), f.asset, f.seller, f.req())
	if err != nil {
		t.Fatal(err)
	}
	if err := f.st.Update(func(x *store.State) error { x.Escrows[recs[0].SPK] = recs[0]; return nil }); err != nil {
		t.Fatal(err)
	}
	escrowSpk, _ := hex.DecodeString(recs[0].SPK)
	buyerSpk, _ := hex.DecodeString(enclaveSpk(t, f.s, f.buyer, f.asset))
	otherSpk, _ := hex.DecodeString(enclaveSpk(t, f.s, f.other, f.asset))
	sellerSpk, _ := hex.DecodeString(enclaveSpk(t, f.s, f.seller, f.asset))
	feeSpk := []byte{0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	spentEscrow := &elements.SpentOutput{Asset: elements.ExplicitAsset(elements.MustHex32(f.asset.ID)), Value: elements.ExplicitValue(1000), ScriptPubKey: escrowSpk}
	spentFee := &elements.SpentOutput{Asset: elements.ExplicitAsset(elements.MustHex32(strings.Repeat("44", 32))), Value: elements.ExplicitValue(5000), ScriptPubKey: feeSpk}
	claimTx := func(outs ...*elements.TxOut) *elements.Tx {
		return &elements.Tx{Version: 2, In: []*elements.TxIn{{}, {}}, Out: outs}
	}
	spent := []*elements.SpentOutput{spentEscrow, spentFee}
	ins := []escrowInput{{Input: 0}}

	if _, _, idx, err := f.s.escrowClaim(claimTx(f.out(buyerSpk, 1000)), spent, f.asset, f.seller, ins); err != nil || idx != 0 {
		t.Fatalf("a good claim: %v", err)
	}
	for name, c := range map[string]struct {
		tx     *elements.Tx
		spent  []*elements.SpentOutput
		seller *store.User
		ins    []escrowInput
	}{
		"to another holder":          {claimTx(f.out(otherSpk, 1000)), spent, f.seller, ins},
		"back to the seller":         {claimTx(f.out(sellerSpk, 1000)), spent, f.seller, ins},
		"one atom short":             {claimTx(f.out(buyerSpk, 999)), spent, f.seller, ins},
		"split in two":               {claimTx(f.out(buyerSpk, 500), f.out(buyerSpk, 500)), spent, f.seller, ins},
		"named as another's escrow":  {claimTx(f.out(buyerSpk, 1000)), spent, f.other, ins},
		"an input that is no escrow": {claimTx(f.out(buyerSpk, 1000)), spent, f.seller, []escrowInput{{Input: 1}}},
		"two escrows named":          {claimTx(f.out(buyerSpk, 1000)), spent, f.seller, []escrowInput{{Input: 0}, {Input: 1}}},
		"another coin of the asset":  {claimTx(f.out(buyerSpk, 1000)), []*elements.SpentOutput{spentEscrow, {Asset: spentEscrow.Asset, Value: elements.ExplicitValue(7), ScriptPubKey: sellerSpk}}, f.seller, ins},
	} {
		if _, _, _, err := f.s.escrowClaim(c.tx, c.spent, f.asset, c.seller, c.ins); err == nil {
			t.Fatalf("%s: claim accepted", name)
		}
	}

	// The cut-off: an hour before t_seq, by this server's clock or the chain's.
	tSeq := time.Unix(int64(f.tSeq), 0)
	f.now = tSeq.Add(-claimCutoff - time.Second)
	if _, _, _, err := f.s.escrowClaim(claimTx(f.out(buyerSpk, 1000)), spent, f.asset, f.seller, ins); err != nil {
		t.Fatalf("a claim a second before the cut-off: %v", err)
	}
	f.now = tSeq.Add(-claimCutoff)
	_, _, _, err = f.s.escrowClaim(claimTx(f.out(buyerSpk, 1000)), spent, f.asset, f.seller, ins)
	wantRefusal(t, err, "claim_cutoff")
}
