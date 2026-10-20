package server

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/ConcatenaLabs/openamp/openampd/internal/elements"
	"github.com/ConcatenaLabs/openamp/openampd/internal/fastmerkle"
	"github.com/ConcatenaLabs/openamp/openampd/internal/store"
)

// The verifier asset's token: a network-enforced asset's resume, out of the
// server wallet.
//
// OpenDAMP's confinement rests on one invariant no covenant of the asset can
// check: q of the verifier asset V never exists outside a verifier covenant
// (opendamp's DESIGN.md section 2.1). A halt burns V, and V's reissuance token
// is what resumes the asset. In this server's wallet that token could mint V to
// any address, a bypass of every holder's policy. It lives instead in
// sequentia-contracts' verifier-token covenant (templates/verifier_token,
// docs/verifier-token.md), which reissues exactly q of V, signed by the asset's
// issuer update key, only into the verifier covenant it records. This server
// never holds that key: it moves the token in and shows where it is; the
// issuer records at a halt and resumes with the token-covenants tool.

// newVerifierToken derives V's token covenant recording the verifier whose
// scriptPubKey is verifierSpk (hex). Ids and entropy are display hex.
func (s *Server) newVerifierToken(vAsset, vToken, vEntropy string, q uint64, issuerKey, verifierSpk string) (*store.VerifierToken, []byte, error) {
	var inst map[string]json.RawMessage
	if err := s.runTool(&inst, nil, "verifier-token", "instance",
		"--verifier-asset", vAsset, "--token", vToken, "--entropy", vEntropy,
		"--amount", strconv.FormatUint(q, 10), "--issuer-key", issuerKey,
		"--verifier", verifierSpk, "--genesis", displayHash(s.genesis)); err != nil {
		return nil, nil, err
	}
	// For convenience only; not part of the instance file.
	delete(inst, "address")
	delete(inst, "verifier_script_pubkey")
	file, err := json.Marshal(inst)
	if err != nil {
		return nil, nil, err
	}
	var a toolAddress
	if err := s.withInstance(file, func(path string) error {
		return s.runTool(&a, nil, "verifier-token", "address", "--instance", path, "--verifier", verifierSpk)
	}); err != nil {
		return nil, nil, err
	}
	spk, err := hex.DecodeString(a.ScriptPubKey)
	if err != nil || len(spk) != 34 {
		return nil, nil, fmt.Errorf("token-covenants verifier-token address: bad script_pubkey %q", a.ScriptPubKey)
	}
	return &store.VerifierToken{
		Instance: file, Token: vToken, Entropy: vEntropy, Recorded: verifierSpk,
		ScriptPubKey: hex.EncodeToString(spk), Address: s.chainAddress(spk, a.Address),
	}, spk, nil
}

// verifierIssuance reads V's issuance from the transaction that made it: the
// final entropy, V, its token (display hex) and the token amount created.
func (s *Server) verifierIssuance(txid string) (entropy, asset, token string, tokenAtoms uint64, err error) {
	raw, err := s.rawTxHex(txid)
	if err != nil {
		return "", "", "", 0, err
	}
	tx, err := elements.DeserializeTx(mustHexBytes(raw))
	if err != nil {
		return "", "", "", 0, err
	}
	for _, in := range tx.In {
		if in.Issuance == nil || in.Issuance.Nonce != ([32]byte{}) {
			continue // no issuance, or a reissuance
		}
		e, a, t := fastmerkle.DeriveIssuanceIDs(in.Prevout.Hash, in.Prevout.N, in.Issuance.Entropy)
		n, _ := elements.ExplicitValueAmount(in.Issuance.InflationKeys)
		return displayHash(e), displayHash(a), displayHash(t), n, nil
	}
	return "", "", "", 0, fmt.Errorf("transaction %s issues no asset", txid)
}

// verifierTokenView is what the asset and supply reads show of V's token.
func verifierTokenView(v *store.VerifierToken) map[string]any {
	if v == nil {
		return nil
	}
	view := map[string]any{
		"token": v.Token, "recorded_verifier_spk": v.Recorded,
		"address": v.Address, "script_pubkey": v.ScriptPubKey,
		"coin": fmt.Sprintf("%s:%d", v.CoinTxid, v.CoinVout), "token_atoms": v.TokenAtoms,
	}
	if v.IssuedTokenAtoms != 0 {
		view["issued_token_atoms"] = v.IssuedTokenAtoms
		view["holds_the_whole_token"] = v.TokenAtoms == v.IssuedTokenAtoms
	}
	return view
}

// handleVerifierTokenMove is POST /v1/issuer/verifier-token: move a
// network-enforced asset's verifier-asset token out of this server's wallet
// into its covenant, recording the asset's current verifier, for an asset
// issued before the token went straight there. Every coin of the token the
// wallet holds moves, in one transaction. Pasting it again for an asset already
// moved answers with where the token is.
func (s *Server) handleVerifierTokenMove(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Asset string `json:"asset"`
	}
	if err := decodeBody(r, &req); err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	var asset *store.Asset
	s.st.View(func(st *store.State) {
		if a, ok := st.Assets[req.Asset]; ok {
			cp := *a
			if a.Damp != nil {
				d := *a.Damp
				cp.Damp = &d
			}
			asset = &cp
		}
	})
	if asset == nil {
		httpErr(w, 404, "unknown asset")
		return
	}
	if asset.Enforcement != "damp" || asset.Damp == nil {
		httpErr(w, 409, "asset %s is not network-enforced: it has no verifier asset", asset.ID)
		return
	}
	if asset.Damp.VerifierToken != nil {
		httpJSON(w, map[string]any{"asset": asset.ID, "status": "already in its covenant",
			"verifier_token": verifierTokenView(asset.Damp.VerifierToken)})
		return
	}
	if s.tool == nil {
		httpErr(w, 501, supplyCapNotConfigured)
		return
	}
	d := asset.Damp
	if d.VerifierSPK == "" || d.IssuerUpdateKey == "" || d.VerifierAmount == 0 {
		httpErr(w, 500, "asset %s's record names no verifier, issuer key or verifier amount", asset.ID)
		return
	}
	entropy, vAsset, vToken, issued, err := s.verifierIssuance(d.VerifierIssueTxid)
	if err != nil {
		httpErr(w, 502, "read V's issuance %s: %v", d.VerifierIssueTxid, err)
		return
	}
	if vAsset != d.VerifierAsset {
		httpErr(w, 500, "transaction %s issues %s, not this asset's verifier asset %s", d.VerifierIssueTxid, vAsset, d.VerifierAsset)
		return
	}
	all, err := s.wallet.ListUnspentAll()
	if err != nil {
		httpErr(w, 502, "list wallet coins: %v", err)
		return
	}
	var tokens []rpcConfLite
	var total uint64
	blinded := false
	for _, u := range all {
		if u.Asset == vToken && u.Spendable {
			tokens = append(tokens, rpcConfLite{u.TxID, u.Vout, sats(u.Amount)})
			total += sats(u.Amount)
			blinded = blinded || u.Blinded()
		}
	}
	if len(tokens) == 0 {
		httpErr(w, 409, "the server wallet holds no coin of V's token %s: it moved already, or it was never here", vToken)
		return
	}
	vt, spk, err := s.newVerifierToken(d.VerifierAsset, vToken, entropy, d.VerifierAmount, d.IssuerUpdateKey, d.VerifierSPK)
	if err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	feeIn, err := s.feeUTXO(3)
	if err != nil {
		httpErr(w, feeStatus(err), "fee funding: %v", err)
		return
	}
	feeAssetID := elements.MustHex32(feeIn.asset)
	tx := &elements.Tx{Version: 2}
	for _, t := range tokens {
		tx.In = append(tx.In, &elements.TxIn{Prevout: elements.OutPoint{Hash: internalHash(t.txid), N: t.vout}})
	}
	tx.In = append(tx.In, &elements.TxIn{Prevout: elements.OutPoint{Hash: internalHash(feeIn.txid), N: feeIn.vout}})
	// The token, explicitly and with no nonce: the covenant reads only explicit coins.
	tx.Out = append(tx.Out, &elements.TxOut{Asset: elements.ExplicitAsset(elements.MustHex32(vToken)),
		Value: elements.ExplicitValue(total), Nonce: elements.NullNonce(), ScriptPubKey: spk})
	// The fee change: blinded only when a token coin was, to balance its blinders.
	changeNonce, changeSpk := elements.NullNonce(), []byte(nil)
	if blinded {
		changeNonce, changeSpk, err = s.blindedWalletOutput()
	} else {
		var addr, spkHex string
		if addr, err = s.wallet.GetNewAddress(); err == nil {
			spkHex, err = s.addressScriptPubKey(addr)
			changeSpk = mustHexBytes(spkHex)
		}
	}
	if err != nil {
		httpErr(w, 502, "fee change output: %v", err)
		return
	}
	tx.Out = append(tx.Out,
		&elements.TxOut{Asset: elements.ExplicitAsset(feeAssetID), Value: elements.ExplicitValue(feeIn.sats - feeIn.fee),
			Nonce: changeNonce, ScriptPubKey: changeSpk},
		&elements.TxOut{Asset: elements.ExplicitAsset(feeAssetID), Value: elements.ExplicitValue(feeIn.fee),
			Nonce: elements.NullNonce(), ScriptPubKey: nil},
	)
	tx.NormalizeWitness()
	if blinded {
		if tx, err = s.blindTx(tx); err != nil {
			httpErr(w, 500, "blind the fee change: %v", err)
			return
		}
	}
	signed, err := s.wallet.SignRawTransactionWithWallet(hex.EncodeToString(tx.Serialize()))
	if err != nil {
		httpErr(w, 502, "sign: %v", err)
		return
	}
	if !signed.Complete {
		httpErr(w, 502, "move signing incomplete: %+v", signed.Errors)
		return
	}
	if err := s.mempoolGate("verifier-token-move", signed.Hex, map[string]any{"asset": asset.ID}); err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	txid, err := s.wallet.SendRawTransaction(signed.Hex)
	if err != nil {
		httpErr(w, 502, "broadcast: %v", err)
		return
	}
	vt.CoinTxid, vt.CoinVout, vt.TokenAtoms, vt.IssuedTokenAtoms = txid, 0, total, issued
	if err := s.st.Update(func(st *store.State) error {
		st.Assets[asset.ID].Damp.VerifierToken = vt
		return nil
	}); err != nil {
		httpErr(w, 500, "persist verifier token: %v", err)
		return
	}
	s.st.AppendLog("verifier-token-move", map[string]any{
		"asset": asset.ID, "txid": txid, "token": vToken, "token_atoms": total,
		"address": vt.Address, "recorded_verifier_spk": vt.Recorded,
	})
	httpJSON(w, map[string]any{"asset": asset.ID, "status": "moved", "txid": txid,
		"verifier_token": verifierTokenView(vt)})
}
