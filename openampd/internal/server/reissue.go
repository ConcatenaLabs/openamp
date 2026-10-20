package server

import (
	"encoding/hex"
	"net/http"
	"strconv"

	"github.com/ConcatenaLabs/openamp/openampd/internal/elements"
	"github.com/ConcatenaLabs/openamp/openampd/internal/store"
)

// OA-6: mint MORE of an existing restricted asset into a target enclave, for a
// Depository-Receipt programme whose circulating supply must change for real.
//
// Every mint goes through the asset's supply cap (supplycap.go): the covenant
// that holds the reissuance token reissues on its own input, counts the amount
// against the cap fixed when it was made, and re-creates itself with the new
// count. The token is explicit, as the covenant requires; Sequentia reissues
// from an explicit token directly (its issuance carries a fixed sentinel nonce
// in place of a blinding factor), so there is nothing to blind first. The mint
// is built by the token-covenants tool and only broadcast after
// testmempoolaccept accepts it. A caller request_id makes the mint idempotent:
// a retry returns the same txid and never mints twice.

// blindedWalletOutput resolves a fresh per-call blinded (blech32) wallet
// destination: its blinding pubkey (used as an output nonce) and its
// unconfidential scriptPubKey. It forces blinding for this output without
// touching the node's -blindedaddresses flag.
func (s *Server) blindedWalletOutput() (nonce []byte, spk []byte, err error) {
	addr, err := s.wallet.GetNewBlindedAddress()
	if err != nil {
		return nil, nil, err
	}
	info, err := s.wallet.GetAddressInfo(addr)
	if err != nil {
		return nil, nil, err
	}
	if info.ConfidentialKey == "" {
		return nil, nil, errNoBlinding
	}
	spkHex := info.ScriptPubKey
	if info.Unconfidential != "" && info.Unconfidential != addr {
		if info2, err := s.wallet.GetAddressInfo(info.Unconfidential); err == nil && info2.ScriptPubKey != "" {
			spkHex = info2.ScriptPubKey
		}
	}
	return mustHexBytes(info.ConfidentialKey), mustHexBytes(spkHex), nil
}

var errNoBlinding = &PolicyRefusal{Reason: "wallet returned no blinding key for a per-call blinded address"}

// handleReissue mints more of an existing restricted asset into a target
// enclave, through the asset's supply cap.
func (s *Server) handleReissue(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Asset     string `json:"asset"`
		TargetAID string `json:"target_aid"`
		Atoms     uint64 `json:"atoms"`
		RequestID string `json:"request_id"` // idempotency key; a retry returns the same txid
		// Confidential is refused for a mint: the covenant reads the amount from
		// the issuance on its own input, which is explicit, so blinding the
		// minted output would hide nothing. The holder blinds a later transfer.
		Confidential bool `json:"confidential"`
	}
	if err := decodeBody(r, &req); err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	if req.Atoms == 0 {
		httpErr(w, 400, "atoms must be greater than zero")
		return
	}
	if req.RequestID == "" {
		httpErr(w, 400, "request_id is required (idempotency key; a retry returns the same reissue txid)")
		return
	}
	if req.Confidential {
		httpErr(w, 400, "a mint cannot be confidential: the supply cap counts the issuance amount on its own input, which is public, so a blinded output would hide nothing. Mint explicitly; the holder chooses confidentiality on a later transfer")
		return
	}
	targetTree, _, asset, err := s.enclaveFor(req.TargetAID, req.Asset)
	if err != nil {
		httpErr(w, 404, "%v", err)
		return
	}
	// A damp asset's units live in covenants, not enclaves: a reissuance would
	// have to mint into C_U for a named recipient key and lock a verifier output,
	// which is the damp issuance path, not this one.
	if refuseDampCosign(w, asset) {
		return
	}
	if asset.Entropy == "" || asset.Token == "" {
		httpErr(w, 501, "reissuance needs an asset issued with OA-6 (its entropy and token id were not recorded)")
		return
	}

	// Idempotency: a completed reissue for this request_id returns its txid.
	if txid, ok := s.st.GetReissue(req.RequestID); ok {
		httpJSON(w, map[string]any{"reissue_txid": txid, "status": "done", "idempotent": true})
		return
	}
	// Crash-window recovery: a reservation exists (the tx was built + signed and its
	// txid fixed) but MarkReissue was lost. Rebroadcast the IDENTICAL stored tx: the
	// node dedupes (same txid), and if the first reissuance already confirmed the
	// rebroadcast is a harmless no-op. Either way the mint is the same single tx, so
	// this can never mint a second time. Then complete the idempotency record and
	// the supply cap's next coin.
	if pr, ok := s.st.GetPendingReissue(req.RequestID); ok {
		if _, err := s.wallet.SendRawTransaction(pr.SignedHex); err != nil {
			// Already-in-mempool / already-in-chain / spent-inputs all mean the
			// reserved tx is (or was) live; the reserved txid is authoritative.
			s.st.AppendLog("reissue-rebroadcast", map[string]any{"request_id": req.RequestID, "txid": pr.Txid, "note": err.Error()})
		}
		if pr.Asset != "" {
			if err := s.st.Update(func(st *store.State) error {
				if a, ok := st.Assets[pr.Asset]; ok && a.SupplyCap != nil && a.SupplyCap.CoinTxid != pr.Txid {
					a.SupplyCap.CoinTxid, a.SupplyCap.CoinVout = pr.Txid, 0
					a.SupplyCap.Minted = pr.NextMinted
					a.SupplyCap.ScriptPubKey, a.SupplyCap.Address = pr.NextScriptPubKey, pr.NextAddress
				}
				return nil
			}); err != nil {
				httpErr(w, 500, "persist supply cap: %v", err)
				return
			}
		}
		if err := s.st.MarkReissue(req.RequestID, pr.Txid); err != nil {
			httpErr(w, 500, "persist reissue: %v", err)
			return
		}
		httpJSON(w, map[string]any{"reissue_txid": pr.Txid, "status": "done", "idempotent": true})
		return
	}

	// The supply cap: configured here, holding the token, with room for the mint.
	if s.tool == nil {
		httpErr(w, 501, supplyCapNotConfigured)
		return
	}
	c := asset.SupplyCap
	if c == nil {
		httpErr(w, 409, "this asset's reissuance token is in no supply cap, so it cannot be minted: move it in with POST /v1/issuer/supply-cap")
		return
	}
	if c.OperatorKey != s.capOperatorKey {
		httpErr(w, 409, "this asset's supply cap is held under operator key %s, not this server's: only that key's holder mints", c.OperatorKey)
		return
	}
	if total := c.Minted + req.Atoms; total < c.Minted || total > c.Cap {
		httpErr(w, 409, "a mint of %d would bring the total minted through the supply cap above its cap of %d (%d minted, %d left)",
			req.Atoms, c.Cap, c.Minted, c.Cap-min(c.Cap, c.Minted))
		return
	}
	if !s.utxoUnspent(c.CoinTxid, c.CoinVout) {
		httpErr(w, 409, "the supply cap's coin %s:%d is spent by a transaction this server did not make (a rekey by the cold key?): record it with POST /v1/issuer/supply-cap/rekey", c.CoinTxid, c.CoinVout)
		return
	}
	signedHex, built, err := s.capMintTx(asset, targetTree.ScriptPubKey(), req.Atoms)
	if err != nil {
		if pr, ok := err.(*PolicyRefusal); ok {
			httpErr(w, 503, "%s", pr.Reason)
			return
		}
		httpErr(w, 502, "%v", err)
		return
	}
	// Safety gate: never broadcast a mint the node would reject.
	if err := s.mempoolGate("reissue", signedHex, map[string]any{
		"asset": asset.ID, "target": req.TargetAID, "request_id": req.RequestID,
	}); err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	// Compute the txid deterministically from the signed tx and RESERVE the
	// request_id (the exact signed tx + txid + the covenant's next coin) BEFORE
	// broadcast: the reservation is the guard against a double mint if this
	// process dies between broadcast and the idempotency write.
	rawSigned, err := hex.DecodeString(signedHex)
	if err != nil {
		httpErr(w, 500, "decode signed reissuance: %v", err)
		return
	}
	signedTx, err := elements.DeserializeTx(rawSigned)
	if err != nil {
		httpErr(w, 500, "parse signed reissuance: %v", err)
		return
	}
	reissueTxid := signedTx.TxID()
	nextMinted, err := strconv.ParseUint(built.NextMinted, 10, 64)
	if err != nil || nextMinted != c.Minted+req.Atoms {
		httpErr(w, 500, "the tool's next count %q is not %d", built.NextMinted, c.Minted+req.Atoms)
		return
	}
	nextSpk := mustHexBytes(built.Successor.ScriptPubKey)
	nextAddr := s.chainAddress(nextSpk, built.Successor.Address)
	if err := s.st.ReservePendingReissue(req.RequestID, store.PendingReissue{
		SignedHex: signedHex, Txid: reissueTxid, Asset: asset.ID,
		NextMinted: nextMinted, NextScriptPubKey: built.Successor.ScriptPubKey, NextAddress: nextAddr,
	}); err != nil {
		httpErr(w, 500, "reserve reissue: %v", err)
		return
	}
	txid, err := s.wallet.SendRawTransaction(signedHex)
	if err != nil {
		httpErr(w, 502, "broadcast: %v", err)
		return
	}
	if err := s.st.Update(func(st *store.State) error {
		a := st.Assets[asset.ID].SupplyCap
		a.CoinTxid, a.CoinVout, a.Minted = reissueTxid, 0, nextMinted
		a.ScriptPubKey, a.Address = built.Successor.ScriptPubKey, nextAddr
		return nil
	}); err != nil {
		httpErr(w, 500, "persist supply cap: %v", err)
		return
	}
	// Record so a retry short-circuits to the completed record (also clears the
	// pending reservation).
	if err := s.st.MarkReissue(req.RequestID, txid); err != nil {
		httpErr(w, 500, "persist reissue: %v", err)
		return
	}
	s.st.AppendLog("reissue", map[string]any{
		"asset": asset.ID, "target": req.TargetAID, "atoms": req.Atoms, "txid": txid,
		"minted_through_cap": nextMinted, "cap": c.Cap,
	})
	httpJSON(w, map[string]any{
		"reissue_txid": txid, "status": "broadcast", "target_aid": req.TargetAID, "atoms": req.Atoms,
		"minted_atoms": nextMinted, "cap_atoms": c.Cap, "room_atoms": c.Cap - nextMinted,
	})
}
