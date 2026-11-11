package server

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ConcatenaLabs/openamp/openampd/internal/elements"
	"github.com/ConcatenaLabs/openamp/openampd/internal/store"
)

type htlcFixture struct {
	s             *Server
	st            *store.Store
	asset         *store.Asset
	seller, buyer *store.User
	other         *store.User
	hash          [32]byte
	now           time.Time
	tSeq          uint32
}

func newHTLCFixture(t *testing.T, rules store.Rules) *htlcFixture {
	t.Helper()
	s, st, _ := newOA3Server(t)
	f := &htlcFixture{s: s, st: st}
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

func (f *htlcFixture) htlcSpk(t *testing.T, buyer *store.User, hash [32]byte, tSeq uint32, value uint64) []byte {
	t.Helper()
	tree, err := f.s.htlcTree(f.asset, f.seller, buyer, hash, tSeq, value)
	if err != nil {
		t.Fatal(err)
	}
	return tree.ScriptPubKey()
}

func (f *htlcFixture) out(spk []byte, value uint64) *elements.TxOut {
	return &elements.TxOut{
		Asset: elements.ExplicitAsset(elements.MustHex32(f.asset.ID)), Value: elements.ExplicitValue(value),
		Nonce: elements.NullNonce(), ScriptPubKey: spk,
	}
}

func (f *htlcFixture) lockTx(t *testing.T, value uint64) *elements.Tx {
	return &elements.Tx{Version: 2, Out: []*elements.TxOut{f.out(f.htlcSpk(t, f.buyer, f.hash, f.tSeq, value), value)}}
}

func (f *htlcFixture) req() []htlcOutput {
	return []htlcOutput{{Output: 0, BuyerAID: f.buyer.AID, Hash: hex.EncodeToString(f.hash[:]), TSeq: f.tSeq}}
}

func wantRefusal(t *testing.T, err error, code string) {
	t.Helper()
	pr, ok := err.(*PolicyRefusal)
	if !ok || pr.Code != code {
		t.Fatalf("want refusal %q, got %v (%T)", code, err, err)
	}
}

// The lock: the HTLC its terms describe, for a registered buyer who could
// receive it now, admitted as the seller's own coin.
func TestHTLCLockAdmission(t *testing.T) {
	f := newHTLCFixture(t, store.Rules{AllowedCategories: []string{"kyc:eu"}})
	admitted, recs, err := f.s.admitHTLCOutputs(f.lockTx(t, 1000), f.asset, f.seller, f.req())
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Value != 1000 || recs[0].BuyerAID != f.buyer.AID || admitted[recs[0].SPK].AID != f.seller.AID {
		t.Fatalf("admitted %v, records %+v", admitted, recs[0])
	}
	// The HTLC is the seller's own coin: the lock moves nothing to anyone.
	atoms := map[string]uint64{}
	if err := f.s.checkTransferAdmitting(f.lockTx(t, 1000), f.asset, f.seller, atoms, admitted); err != nil || len(atoms) != 0 {
		t.Fatalf("lock judged as a transfer: %v %v", err, atoms)
	}

	cases := []struct {
		name string
		edit func(r []htlcOutput, tx *elements.Tx)
		code string
	}{
		{"terms of another hash", func(r []htlcOutput, tx *elements.Tx) { r[0].Hash = strings.Repeat("ab", 32) }, "htlc"},
		{"a height t_seq", func(r []htlcOutput, tx *elements.Tx) { r[0].TSeq = 499_999_999 }, "htlc"},
		{"t_seq too soon", func(r []htlcOutput, tx *elements.Tx) { r[0].TSeq = uint32(f.now.Add(90 * time.Minute).Unix()) }, "htlc"},
		{"t_seq too far", func(r []htlcOutput, tx *elements.Tx) { r[0].TSeq = uint32(f.now.Add(8 * 24 * time.Hour).Unix()) }, "htlc"},
		{"unregistered buyer", func(r []htlcOutput, tx *elements.Tx) { r[0].BuyerAID = strings.Repeat("cd", 20) }, "unregistered"},
		{"the seller as buyer", func(r []htlcOutput, tx *elements.Tx) { r[0].BuyerAID = f.seller.AID }, "htlc"},
		{"output out of range", func(r []htlcOutput, tx *elements.Tx) { r[0].Output = 3 }, "htlc"},
		{"another asset", func(r []htlcOutput, tx *elements.Tx) {
			tx.Out[0].Asset = elements.ExplicitAsset(elements.MustHex32(strings.Repeat("99", 32)))
		}, "htlc"},
	}
	for _, c := range cases {
		r := f.req()
		tx := f.lockTx(t, 1000)
		c.edit(r, tx)
		_, _, err := f.s.admitHTLCOutputs(tx, f.asset, f.seller, r)
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
	tx := &elements.Tx{Version: 2, Out: []*elements.TxOut{f.out(f.htlcSpk(t, noCat, f.hash, f.tSeq, 1000), 1000)}}
	_, _, err = f.s.admitHTLCOutputs(tx, f.asset, f.seller, r)
	wantRefusal(t, err, "category")
	if err := f.st.Update(func(x *store.State) error { x.Users[f.buyer.AID].Frozen = true; return nil }); err != nil {
		t.Fatal(err)
	}
	_, _, err = f.s.admitHTLCOutputs(f.lockTx(t, 1000), f.asset, f.seller, f.req())
	wantRefusal(t, err, "frozen")
}

// The claim: one HTLC of the sender's, before the cut-off, its whole amount
// to its buyer's enclave and nowhere else.
func TestHTLCClaim(t *testing.T) {
	f := newHTLCFixture(t, store.Rules{})
	_, recs, err := f.s.admitHTLCOutputs(f.lockTx(t, 1000), f.asset, f.seller, f.req())
	if err != nil {
		t.Fatal(err)
	}
	if err := f.st.Update(func(x *store.State) error { x.HTLCs[recs[0].SPK] = recs[0]; return nil }); err != nil {
		t.Fatal(err)
	}
	htlcSpk, _ := hex.DecodeString(recs[0].SPK)
	buyerSpk, _ := hex.DecodeString(enclaveSpk(t, f.s, f.buyer, f.asset))
	otherSpk, _ := hex.DecodeString(enclaveSpk(t, f.s, f.other, f.asset))
	sellerSpk, _ := hex.DecodeString(enclaveSpk(t, f.s, f.seller, f.asset))
	feeSpk := []byte{0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	spentHTLC := &elements.SpentOutput{Asset: elements.ExplicitAsset(elements.MustHex32(f.asset.ID)), Value: elements.ExplicitValue(1000), ScriptPubKey: htlcSpk}
	spentFee := &elements.SpentOutput{Asset: elements.ExplicitAsset(elements.MustHex32(strings.Repeat("44", 32))), Value: elements.ExplicitValue(5000), ScriptPubKey: feeSpk}
	claimTx := func(outs ...*elements.TxOut) *elements.Tx {
		return &elements.Tx{Version: 2, In: []*elements.TxIn{{Sequence: 0xffffffff}, {Sequence: 0xffffffff}}, Out: outs}
	}
	spent := []*elements.SpentOutput{spentHTLC, spentFee}
	ins := []htlcInput{{Input: 0}}

	if _, _, idx, err := f.s.htlcClaim(claimTx(f.out(buyerSpk, 1000)), spent, f.asset, f.seller, ins); err != nil || idx != 0 {
		t.Fatalf("a good claim: %v", err)
	}
	for name, c := range map[string]struct {
		tx     *elements.Tx
		spent  []*elements.SpentOutput
		seller *store.User
		ins    []htlcInput
	}{
		"to another holder":         {claimTx(f.out(otherSpk, 1000)), spent, f.seller, ins},
		"back to the seller":        {claimTx(f.out(sellerSpk, 1000)), spent, f.seller, ins},
		"one atom short":            {claimTx(f.out(buyerSpk, 999)), spent, f.seller, ins},
		"split in two":              {claimTx(f.out(buyerSpk, 500), f.out(buyerSpk, 500)), spent, f.seller, ins},
		"named as another's HTLC":   {claimTx(f.out(buyerSpk, 1000)), spent, f.other, ins},
		"an input that is no HTLC":  {claimTx(f.out(buyerSpk, 1000)), spent, f.seller, []htlcInput{{Input: 1}}},
		"two HTLCs named":           {claimTx(f.out(buyerSpk, 1000)), spent, f.seller, []htlcInput{{Input: 0}, {Input: 1}}},
		"another coin of the asset": {claimTx(f.out(buyerSpk, 1000)), []*elements.SpentOutput{spentHTLC, {Asset: spentHTLC.Asset, Value: elements.ExplicitValue(7), ScriptPubKey: sellerSpk}}, f.seller, ins},
	} {
		if _, _, _, err := f.s.htlcClaim(c.tx, c.spent, f.asset, c.seller, c.ins); err == nil {
			t.Fatalf("%s: claim accepted", name)
		}
	}

	// The cut-off: an hour before t_seq, by this server's clock or the chain's.
	tSeq := time.Unix(int64(f.tSeq), 0)
	f.now = tSeq.Add(-claimCutoff - time.Second)
	if _, _, _, err := f.s.htlcClaim(claimTx(f.out(buyerSpk, 1000)), spent, f.asset, f.seller, ins); err != nil {
		t.Fatalf("a claim a second before the cut-off: %v", err)
	}
	f.now = tSeq.Add(-claimCutoff)
	_, _, _, err = f.s.htlcClaim(claimTx(f.out(buyerSpk, 1000)), spent, f.asset, f.seller, ins)
	wantRefusal(t, err, "claim_cutoff")
}

// Velocity and claims. A re-claim of the same HTLC (a higher fee, after a
// stuck claim) is the same movement as the first claim and is judged without
// it; a claim record that is never mined stops counting at T_seq, and any
// other unconfirmed record at its expiry (#49).
func TestHTLCReclaimVelocity(t *testing.T) {
	f := newHTLCFixture(t, store.Rules{VelocityMaxAtoms: 1500, VelocityWindowBlocks: 100})
	_, recs, err := f.s.admitHTLCOutputs(f.lockTx(t, 1000), f.asset, f.seller, f.req())
	if err != nil {
		t.Fatal(err)
	}
	if err := f.st.Update(func(x *store.State) error {
		x.Height = 500
		x.HTLCs[recs[0].SPK] = recs[0]
		// 400 atoms the seller sent earlier, mined inside the window.
		x.Transfers = append(x.Transfers, store.TransferRecord{Txid: "aa", Asset: f.asset.ID, SenderAID: f.seller.AID, Atoms: 400, Height: 450})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	htlcSpk, _ := hex.DecodeString(recs[0].SPK)
	buyerSpk, _ := hex.DecodeString(enclaveSpk(t, f.s, f.buyer, f.asset))
	spent := []*elements.SpentOutput{
		{Asset: elements.ExplicitAsset(elements.MustHex32(f.asset.ID)), Value: elements.ExplicitValue(1000), ScriptPubKey: htlcSpk},
		{Asset: elements.ExplicitAsset(elements.MustHex32(strings.Repeat("44", 32))), Value: elements.ExplicitValue(5000), ScriptPubKey: []byte{0x51, 0x20, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}},
	}
	claim := func(fee uint64) *elements.Tx {
		feeAsset := elements.ExplicitAsset(elements.MustHex32(strings.Repeat("44", 32)))
		return &elements.Tx{Version: 2, In: []*elements.TxIn{{Sequence: 0xffffffff}, {Sequence: 0xffffffff}}, Out: []*elements.TxOut{
			f.out(buyerSpk, 1000),
			{Asset: feeAsset, Value: elements.ExplicitValue(5000 - fee), Nonce: elements.NullNonce(), ScriptPubKey: spent[1].ScriptPubKey},
			{Asset: feeAsset, Value: elements.ExplicitValue(fee), Nonce: elements.NullNonce()},
		}}
	}
	f.s.signer = stubPolicySigner{}
	cosign := func(tx *elements.Tx) int {
		w := httptest.NewRecorder()
		f.s.handleHTLCClaim(w, tx, spent, f.asset, f.seller, []htlcInput{{Input: 0}})
		if w.Code != 200 {
			t.Logf("co-sign: %d %s", w.Code, w.Body.String())
		}
		return w.Code
	}
	if code := cosign(claim(100)); code != 200 {
		t.Fatalf("first claim: %d", code)
	}
	// The re-claim at a higher fee: 400 + 1000 is inside 1500, whereas
	// counting the first claim as well would be 2400.
	if code := cosign(claim(300)); code != 200 {
		t.Fatalf("re-claim of the same HTLC refused: %d", code)
	}
	n := 0
	f.s.st.View(func(x *store.State) {
		for _, r := range x.Transfers {
			if r.Kind == "htlc-claim" {
				n++
			}
		}
	})
	if n != 1 {
		t.Fatalf("%d claim records, want 1", n)
	}
	// Another movement is still judged with the claim counted.
	err = f.s.checkRules(f.asset, f.seller, map[string]uint64{f.other.AID: 101}, 0, 500)
	wantRefusal(t, err, "velocity")

	// The claim was never mined: it counts at T_seq and after, for a
	// signature never expires (PV5 V3, #65).
	f.now = time.Unix(int64(f.tSeq), 0)
	err = f.s.checkRules(f.asset, f.seller, map[string]uint64{f.other.AID: 101}, 0, 500)
	wantRefusal(t, err, "velocity")
	claimRec := func() store.TransferRecord {
		var r store.TransferRecord
		f.s.st.View(func(x *store.State) {
			for _, t := range x.Transfers {
				if t.Kind == "htlc-claim" {
					r = t
				}
			}
		})
		return r
	}
	op := claimRec().ID
	if op != outpointString(claim(100).In[0].Prevout) {
		t.Fatalf("the claim record is keyed %q, not on the HTLC's outpoint", op)
	}
	// PV5 V2: a superseded claim mined (another txid, a claim's witness) is
	// the claim, counted at its height.
	r := claimRec()
	settleBySpends(&r, map[string]blockSpend{op: {txid: "aa", height: 499, witness: htlcClaimWitness}})
	if r.Height != 499 || r.Txid != "aa" || r.Kind != "htlc-claim" {
		t.Fatalf("a mined claim of the HTLC was not counted: %+v", r)
	}
	// The HTLC's refund instead (a two-item witness): nothing moved from the
	// seller, and the record is released.
	r = claimRec()
	settleBySpends(&r, map[string]blockSpend{op: {txid: "bb", height: 499, witness: 2}})
	if r.Kind != "released" {
		t.Fatalf("a refund did not release the claim: %+v", r)
	}
	// A mined claim is never replaced by a re-claim, nor co-signed again.
	if err := f.st.Update(func(x *store.State) error {
		for i := range x.Transfers {
			if x.Transfers[i].Kind == "htlc-claim" {
				x.Transfers[i].Height = 499
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if code := cosign(claim(400)); code != 403 {
		t.Fatalf("a claim of an already claimed HTLC: %d", code)
	}
	if claimRec().Height != 499 {
		t.Fatal("the mined claim's record was replaced")
	}
}

// PV5 V1 (#65): two HTLCs of identical terms share a script, not an outpoint;
// claiming the second never replaces the first one's record.
func TestTwinHTLCClaimsKeepTheirRecords(t *testing.T) {
	f := newHTLCFixture(t, store.Rules{VelocityMaxAtoms: 10_000, VelocityWindowBlocks: 100})
	f.s.signer = stubPolicySigner{}
	_, recs, err := f.s.admitHTLCOutputs(f.lockTx(t, 1000), f.asset, f.seller, f.req())
	if err != nil {
		t.Fatal(err)
	}
	if err := f.st.Update(func(x *store.State) error { x.Height = 500; x.HTLCs[recs[0].SPK] = recs[0]; return nil }); err != nil {
		t.Fatal(err)
	}
	spk, _ := hex.DecodeString(recs[0].SPK)
	buyerSpk, _ := hex.DecodeString(enclaveSpk(t, f.s, f.buyer, f.asset))
	fee := elements.ExplicitAsset(elements.MustHex32(strings.Repeat("44", 32)))
	spent := []*elements.SpentOutput{
		{Asset: elements.ExplicitAsset(elements.MustHex32(f.asset.ID)), Value: elements.ExplicitValue(1000), ScriptPubKey: spk},
		{Asset: fee, Value: elements.ExplicitValue(5000), ScriptPubKey: []byte{0x51, 0x20, 1}},
	}
	claimOf := func(vout uint32) *elements.Tx {
		return &elements.Tx{Version: 2, In: []*elements.TxIn{
			{Prevout: elements.OutPoint{N: vout}, Sequence: 0xffffffff}, {Prevout: elements.OutPoint{N: 9}, Sequence: 0xffffffff}},
			Out: []*elements.TxOut{f.out(buyerSpk, 1000), {Asset: fee, Value: elements.ExplicitValue(5000), Nonce: elements.NullNonce()}}}
	}
	for _, vout := range []uint32{0, 1} {
		w := httptest.NewRecorder()
		f.s.handleHTLCClaim(w, claimOf(vout), spent, f.asset, f.seller, []htlcInput{{Input: 0}})
		if w.Code != 200 {
			t.Fatalf("claim of twin %d: %d %s", vout, w.Code, w.Body.String())
		}
	}
	n := 0
	f.s.st.View(func(x *store.State) {
		for _, r := range x.Transfers {
			if r.Kind == "htlc-claim" {
				n++
			}
		}
	})
	if n != 2 {
		t.Fatalf("%d claim records for two twin HTLCs, want 2", n)
	}
	// PV5 S16 (#67): a claim with a lock time, or a non-final input, is
	// refused before anything is signed.
	lt := claimOf(2)
	lt.LockTime = f.tSeq
	nf := claimOf(3)
	nf.In[1].Sequence = 0xfffffffe
	for name, tx := range map[string]*elements.Tx{"a lock time": lt, "a non-final input": nf} {
		w := httptest.NewRecorder()
		f.s.handleHTLCClaim(w, tx, spent, f.asset, f.seller, []htlcInput{{Input: 0}})
		if w.Code != 403 {
			t.Fatalf("a claim with %s: %d", name, w.Code)
		}
	}
}

// PV5 V3 (#65): a held co-sign counts until one of its inputs is spent by
// another transaction, not until a time.
func TestAnUnminedRecordCountsUntilItsInputsGo(t *testing.T) {
	r := store.TransferRecord{Txid: "t1", Height: -1, Inputs: []string{"aa:0", "bb:1"}}
	if !velocityCounts(r, 500, 100, 1<<40) {
		t.Fatal("an unmined record with inputs stopped counting with time")
	}
	settleBySpends(&r, map[string]blockSpend{"bb:1": {txid: "t1", height: 499}})
	if r.Kind == "released" {
		t.Fatal("released when its own transaction spent the input")
	}
	settleBySpends(&r, map[string]blockSpend{"aa:0": {txid: "t2", height: 499}})
	if r.Kind != "released" {
		t.Fatal("not released when another transaction spent an input")
	}
}

func TestVelocityCountsUnconfirmedUntilExpiry(t *testing.T) {
	now := int64(1_800_000_000)
	for _, c := range []struct {
		rec  store.TransferRecord
		want bool
	}{
		{store.TransferRecord{Height: 450}, true},
		{store.TransferRecord{Height: 400}, false},
		{store.TransferRecord{Height: -1, Inputs: []string{"aa:0"}, Expires: now - 1}, true},
		{store.TransferRecord{Height: -1, Expires: now + 1}, true},
		{store.TransferRecord{Height: -1, Expires: now}, false},
		{store.TransferRecord{Height: -1}, true},
	} {
		if got := velocityCounts(c.rec, 500, 100, now); got != c.want {
			t.Fatalf("%+v: counts %v, want %v", c.rec, got, c.want)
		}
	}
}

// stubPolicySigner signs anything with 64 zero bytes: these tests judge what
// the server records, not the signature.
type stubPolicySigner struct{}

func (stubPolicySigner) GeneratePolicyKey() ([32]byte, string, error) { return [32]byte{}, "", nil }
func (stubPolicySigner) Adopt(ref, assetID string) error              { return nil }
func (stubPolicySigner) PolicyPubKey(assetID string) ([32]byte, bool) { return [32]byte{}, true }
func (stubPolicySigner) SignPolicy(assetID string, sighash [32]byte, ctx PolicyContext) ([]byte, error) {
	return make([]byte, 64), nil
}
