package server

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"

	"github.com/ConcatenaLabs/openamp/openampd/internal/elements"
	"github.com/ConcatenaLabs/openamp/openampd/internal/store"
)

// tagDvP domain-separates a sender's signed expiry from every other signature
// its enclave key makes: no transfer sighash can equal this tagged hash.
const tagDvP = "openamp-dvp-v1"

func taggedHash(tag string, msg []byte) [32]byte {
	t := sha256.Sum256([]byte(tag))
	h := sha256.New()
	h.Write(t[:])
	h.Write(t[:])
	h.Write(msg)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ExpiryDigest is what a sender signs to bound a trade in time:
// tagged_hash("openamp-dvp-v1", txid (32 bytes, as displayed) || expires_at
// (8 bytes, big-endian Unix seconds)). The txid excludes witnesses, so the
// expiry binds the trade's body, signed before or after the other parties.
func ExpiryDigest(txid string, expiresAt int64) ([32]byte, error) {
	id, err := hex.DecodeString(txid)
	if err != nil || len(id) != 32 {
		return [32]byte{}, fmt.Errorf("txid must be 64 hex characters")
	}
	msg := make([]byte, 40)
	copy(msg, id)
	binary.BigEndian.PutUint64(msg[32:], uint64(expiresAt))
	return taggedHash(tagDvP, msg), nil
}

// checkExpiry verifies the sender's signed expiry and that it has not passed.
func (s *Server) checkExpiry(tx *elements.Tx, sender *store.User, expiresAt int64, sigHex string) error {
	if expiresAt <= 0 || sigHex == "" {
		return fmt.Errorf("a broadcast needs expires_at and the sender's expiry_sig over it")
	}
	digest, err := ExpiryDigest(tx.TxID(), expiresAt)
	if err != nil {
		return err
	}
	pkb, err := hex.DecodeString(sender.Pubkeys[0])
	if err != nil {
		return err
	}
	pk, err := schnorr.ParsePubKey(pkb)
	if err != nil {
		return err
	}
	raw, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("expiry_sig: %v", err)
	}
	sig, err := schnorr.ParseSignature(raw)
	if err != nil || !sig.Verify(digest[:], pk) {
		return fmt.Errorf("expiry_sig is not the sender's signature over this transaction and expiry")
	}
	if !s.now().Before(time.Unix(expiresAt, 0)) {
		return refuseCode("expired", "the sender's offer expired at %s", time.Unix(expiresAt, 0).UTC().Format(time.RFC3339))
	}
	return nil
}

// completeAndBroadcast puts each claimed input's witness together, the policy
// signature and the sender's (checked against the sighash this server
// computed), and broadcasts. Every other input must arrive signed. Nothing is
// recorded unless the node takes the transaction.
func (s *Server) completeAndBroadcast(tx *elements.Tx, spent []*elements.SpentOutput, sender *store.User,
	policySigs map[int][]byte, userSigs map[string]string, leaf, control []byte) (string, error) {
	pkb, _ := hex.DecodeString(sender.Pubkeys[0])
	pk, err := schnorr.ParsePubKey(pkb)
	if err != nil {
		return "", err
	}
	for len(tx.InWit) < len(tx.In) {
		tx.InWit = append(tx.InWit, &elements.TxInWitness{})
	}
	for idx, polSig := range policySigs {
		sh, err := elements.TaprootSighash(tx, spent, elements.SighashDefault, s.genesis, idx, leaf)
		if err != nil {
			return "", err
		}
		raw, err := hex.DecodeString(userSigs[strconv.Itoa(idx)])
		if err != nil {
			return "", fmt.Errorf("user_sigs[%d]: %v", idx, err)
		}
		sig, err := schnorr.ParseSignature(raw)
		if err != nil || !sig.Verify(sh[:], pk) {
			return "", fmt.Errorf("user_sigs[%d] is not the sender's signature over this input", idx)
		}
		tx.InWit[idx].ScriptWitness = [][]byte{polSig, raw, leaf, control}
	}
	signed := hex.EncodeToString(tx.Serialize())
	if err := s.mempoolGate("cosign-broadcast", signed, map[string]any{"sender": sender.AID}); err != nil {
		return "", err
	}
	return s.wallet.SendRawTransaction(signed)
}
