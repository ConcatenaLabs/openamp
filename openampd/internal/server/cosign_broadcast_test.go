package server

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ConcatenaLabs/openamp/openampd/internal/elements"
	"github.com/ConcatenaLabs/openamp/openampd/internal/store"
)

func keyPair(t *testing.T) ([]byte, string) {
	t.Helper()
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatal(err)
	}
	x := elements.XOnlyFromPriv(priv)
	xh := hex.EncodeToString(x[:])
	rememberTestKey(xh, priv)
	return priv, xh
}

var (
	testKeysMu sync.Mutex
	testKeys   = map[string][]byte{}
)

// rememberTestKey keeps a test user's private key by its x-only key, so a
// test can sign as that user (testSenderSig).
func rememberTestKey(xHex string, priv []byte) {
	testKeysMu.Lock()
	defer testKeysMu.Unlock()
	testKeys[xHex] = append([]byte(nil), priv...)
}

// testSenderSig is the sender's sender_sig for a plain co-sign of tx, or ""
// when the test holds no key for it.
func testSenderSig(t *testing.T, s *Server, tx *elements.Tx, aid string) string {
	t.Helper()
	var x string
	s.st.View(func(st *store.State) {
		if u, ok := st.Users[aid]; ok {
			x = u.Pubkeys[0]
		}
	})
	testKeysMu.Lock()
	priv := testKeys[x]
	testKeysMu.Unlock()
	if priv == nil {
		return ""
	}
	d, err := CosignDigest(tx.TxID())
	if err != nil {
		t.Fatal(err)
	}
	sig, err := elements.SignSchnorr(priv, d)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(sig)
}

// The expiry binds the sender: only the sender's key, over this transaction
// and this time, and only before the time.
func TestCheckExpiry(t *testing.T) {
	s, _, _ := newOA3Server(t)
	now := time.Unix(1_800_000_000, 0)
	s.clock = func() time.Time { return now }
	sellerPriv, sellerX := keyPair(t)
	otherPriv, _ := keyPair(t)
	seller := &store.User{AID: "seller", Pubkeys: []string{sellerX}}
	tx := &elements.Tx{Version: 2, Out: []*elements.TxOut{{Asset: elements.ExplicitAsset(elements.MustHex32(strings.Repeat("11", 32))),
		Value: elements.ExplicitValue(1), Nonce: elements.NullNonce(), ScriptPubKey: []byte{0x51}}}}
	sign := func(priv []byte, at int64) string {
		d, err := ExpiryDigest(tx.TxID(), at)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := elements.SignSchnorr(priv, d)
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(sig)
	}
	later := now.Add(10 * time.Minute).Unix()
	if err := s.checkExpiry(tx, seller, later, sign(sellerPriv, later)); err != nil {
		t.Fatalf("the seller's own expiry: %v", err)
	}
	if err := s.checkExpiry(tx, seller, later, sign(otherPriv, later)); err == nil {
		t.Fatal("an expiry signed by another key was accepted")
	}
	if err := s.checkExpiry(tx, seller, later+1, sign(sellerPriv, later)); err == nil {
		t.Fatal("an expiry signed for another time was accepted")
	}
	past := now.Add(-time.Minute).Unix()
	wantRefusal(t, s.checkExpiry(tx, seller, past, sign(sellerPriv, past)), "expired")
	if err := s.checkExpiry(tx, seller, 0, ""); err == nil {
		t.Fatal("a broadcast without an expiry was accepted")
	}
}

// A plain co-sign is the sender's own request: without the sender's signature
// over the transaction, or with anyone else's, it is refused before anything
// is judged. A counterparty holding the sender's input signature and signed
// expiry (a trade past its expiry) cannot get the policy signature this way
// (proof review PV4, D1).
func TestPlainCosignNeedsTheSender(t *testing.T) {
	s, st, _ := newOA3Server(t)
	issuer := regUser(t, st, nil)
	seller, sellerKey := regUserWithKey(t, st)
	buyer, buyerKey := regUserWithKey(t, st)
	asset := oa3Asset(t, issuer.AID, store.Rules{})
	putAsset(t, st, asset)
	tx := &elements.Tx{Version: 2, In: []*elements.TxIn{{}}, Out: []*elements.TxOut{
		explicitOut(asset.ID, 10, enclaveSpk(t, s, buyer, asset))}}
	tx.NormalizeWitness()
	sign := func(priv []byte) string {
		d, _ := CosignDigest(tx.TxID())
		sig, err := elements.SignSchnorr(priv, d)
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(sig)
	}
	other := &elements.Tx{Version: 2, Out: []*elements.TxOut{explicitOut(asset.ID, 11, enclaveSpk(t, s, buyer, asset))}}
	otherSig := func() string {
		d, _ := CosignDigest(other.TxID())
		sig, _ := elements.SignSchnorr(sellerKey, d)
		return hex.EncodeToString(sig)
	}
	// No signature, the buyer's, the seller's over another transaction, and
	// bytes that are not a signature.
	for _, sig := range []string{"", sign(buyerKey), otherSig(), "zz"} {
		wantRefusal(t, checkSenderSig(tx, seller, sig), "sender_sig")
	}
	if err := checkSenderSig(tx, seller, sign(sellerKey)); err != nil {
		t.Fatalf("the seller's own signature: %v", err)
	}
	// Through the handler: refused before the policy engine runs.
	code, body := callCosignWith(t, s, map[string]any{"tx": hex.EncodeToString(tx.Serialize()), "asset": asset.ID,
		"sender_aid": seller.AID, "inputs": []int{0}, "sender_sig": sign(buyerKey)})
	if code != 403 || !strings.Contains(body, "sender_sig") {
		t.Fatalf("a co-sign signed by the buyer: %d %s", code, body)
	}
}
