package server

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
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
	return priv, hex.EncodeToString(x[:])
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
