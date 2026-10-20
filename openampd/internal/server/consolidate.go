package server

import (
	"encoding/hex"
	"log"
	"math/big"
	"net/http"
	"sort"
	"strings"

	"github.com/ConcatenaLabs/openamp/openampd/internal/elements"
	"github.com/ConcatenaLabs/openamp/openampd/internal/rpc"
)

// Blinded-change consolidation. Confidential builds pay the server's fee
// change to per-call blinded (blech32) addresses, and the fee picker refuses
// blinded coins (a blinded fee input would unbalance a fully explicit
// transaction), so a busy server slowly converts its whole fee float into
// coins it cannot spend as fees. Consolidation sweeps that blinded change back
// into one EXPLICIT coin: manually via POST /v1/issuer/consolidate, and
// automatically when the fee picker comes up empty while blinded coins of an
// accepted fee asset exist.

// consolidateMaxInputs bounds one consolidation's input count; a larger backlog
// drains over successive consolidations.
const consolidateMaxInputs = 20

// dustReserve is the amount kept on the one blinded output a consolidation
// must carry (blinded inputs can never balance into all-explicit outputs; see
// blindTx). Two fees keeps it above any plausible dust floor while leaving the
// overwhelming majority of the swept value explicit.
func dustReserve(fee uint64) uint64 { return 2 * fee }

// explicitFeeCoins lists the wallet's spendable explicit coins (any asset).
func (s *Server) explicitFeeCoins() ([]feeCoin, error) {
	us, err := s.wallet.ListUnspent(1, "")
	if err != nil {
		return nil, err
	}
	out := make([]feeCoin, 0, len(us))
	for _, u := range us {
		if u.Spendable && u.Explicit() {
			out = append(out, feeCoin{txid: u.TxID, vout: u.Vout, sats: sats(u.Amount), asset: u.Asset})
		}
	}
	return out, nil
}

// feeUTXO is THE fee picker for every build path: it chooses the fee asset by
// the wallet rule (feeasset.go) and returns the coin, explicit and verified
// unspent in the global UTXO set (a wallet can list coins another wallet
// spent), worth more than `mult` fees of its asset, with the fee. When no
// explicit coin covers that but blinded coins of an accepted asset exist, it
// consolidates them once and funds the caller directly from the
// consolidation's explicit output (0-conf chaining from the server's own
// change), so the original operation simply proceeds. When nothing can pay,
// the error is a *NoFeeCoin naming the assets the node accepts.
func (s *Server) feeUTXO(mult uint64) (*feeCoin, error) {
	rates, err := s.feeCandidates()
	if err != nil {
		return nil, err
	}
	coins, err := s.explicitFeeCoins()
	if err != nil {
		return nil, err
	}
	for _, c := range pickFeeCoins(s.cfg.FeeSats, rates, coins) {
		if c.sats > mult*c.fee && s.utxoUnspent(c.txid, c.vout) {
			cc := c
			log.Printf("fee: %d atoms of %s, from %s:%d", cc.fee, cc.asset, cc.txid, cc.vout)
			return &cc, nil
		}
	}
	log.Printf("fee: no explicit coin covers %d fees (%d coins listed, rates %v)", mult, len(coins), rates)
	coin, err := s.consolidateBlindedFees(rates, mult)
	if err != nil || coin != nil {
		return coin, err
	}
	return nil, noFeeCoinLine(rates, mult)
}

// blindedFeeCoins picks, among the candidates, the asset whose blinded wallet
// coins (up to consolidateMaxInputs of them) are worth most together, and
// returns those coins, their total and the fee in that asset.
func (s *Server) blindedFeeCoins(rates map[string]uint64) (string, []rpc.ConfUnspent, uint64, uint64, error) {
	all, err := s.wallet.ListUnspentAll()
	if err != nil {
		return "", nil, 0, 0, err
	}
	byAsset := map[string][]rpc.ConfUnspent{}
	sums := map[string]uint64{}
	for _, u := range all {
		a := strings.ToLower(u.Asset)
		if rates[a] == 0 || !u.Blinded() || !u.Spendable || len(byAsset[a]) == consolidateMaxInputs {
			continue
		}
		byAsset[a] = append(byAsset[a], u)
		sums[a] += sats(u.Amount)
	}
	best, bestWorth := "", new(big.Int)
	assets := make([]string, 0, len(sums))
	for a := range sums {
		assets = append(assets, a)
	}
	sort.Strings(assets)
	for _, a := range assets {
		worth := new(big.Int).Mul(new(big.Int).SetUint64(sums[a]), new(big.Int).SetUint64(rates[a]))
		if best == "" || worth.Cmp(bestWorth) > 0 {
			best, bestWorth = a, worth
		}
	}
	if best == "" {
		return "", nil, 0, 0, nil
	}
	fee, ok := feeAtomsAt(s.cfg.FeeSats, rates[best])
	if !ok {
		return "", nil, 0, 0, nil
	}
	return best, byAsset[best], sums[best], fee, nil
}

// consolidateBlindedFees builds, gates and broadcasts one consolidation:
// inputs are up to 20 blinded wallet coins of one accepted asset (the one
// whose blinded coins are worth most); outputs are one EXPLICIT output of
// (sum - fee - dustReserve) to a fresh wallet address, one blinded per-call
// blech32 output carrying dustReserve (the balancing output the blinded inputs
// require), and the fee, all in that asset. Returns the explicit output
// (vout 0) as a spendable coin, or nil,nil when there is nothing to
// consolidate or the blinded balance cannot yield an explicit coin worth more
// than `mult` fees. Serialized so concurrent fee-picker failures consolidate
// once, not once each.
func (s *Server) consolidateBlindedFees(rates map[string]uint64, mult uint64) (*feeCoin, error) {
	s.consolidateMu.Lock()
	defer s.consolidateMu.Unlock()

	asset, coins, sum, fee, err := s.blindedFeeCoins(rates)
	if err != nil {
		return nil, err
	}
	if len(coins) == 0 {
		return nil, nil
	}
	reserve := fee + dustReserve(fee)
	if sum <= reserve || sum-reserve <= mult*fee {
		return nil, nil // too small to yield a usable explicit coin
	}
	explicitSats := sum - reserve

	addr, err := s.wallet.GetNewAddress()
	if err != nil {
		return nil, err
	}
	spkHex, err := s.addressScriptPubKey(addr)
	if err != nil {
		return nil, err
	}
	dustNonce, dustSpk, err := s.blindedWalletOutput()
	if err != nil {
		return nil, err
	}

	feeAssetID := elements.MustHex32(asset)
	tx := &elements.Tx{Version: 2}
	for _, u := range coins {
		tx.In = append(tx.In, &elements.TxIn{Prevout: elements.OutPoint{Hash: internalHash(u.TxID), N: u.Vout}})
	}
	tx.Out = append(tx.Out,
		// vout 0: the majority-explicit sweep destination.
		&elements.TxOut{Asset: elements.ExplicitAsset(feeAssetID), Value: elements.ExplicitValue(explicitSats),
			Nonce: elements.NullNonce(), ScriptPubKey: mustHexBytes(spkHex)},
		// vout 1: the one blinded output the blinded inputs balance into.
		&elements.TxOut{Asset: elements.ExplicitAsset(feeAssetID), Value: elements.ExplicitValue(dustReserve(fee)),
			Nonce: dustNonce, ScriptPubKey: dustSpk},
		&elements.TxOut{Asset: elements.ExplicitAsset(feeAssetID), Value: elements.ExplicitValue(fee),
			Nonce: elements.NullNonce(), ScriptPubKey: nil},
	)
	tx.NormalizeWitness()

	blinded, err := s.blindTx(tx)
	if err != nil {
		return nil, err
	}
	signed, err := s.wallet.SignRawTransactionWithWallet(hex.EncodeToString(blinded.Serialize()))
	if err != nil {
		return nil, err
	}
	if !signed.Complete {
		return nil, &PolicyRefusal{Reason: "consolidation signing incomplete"}
	}
	// Safety gate (W-1): a consolidation the node would reject spends nothing.
	if err := s.mempoolGate("consolidate", signed.Hex, map[string]any{"inputs": len(coins)}); err != nil {
		return nil, err
	}
	// The txid comes from the signed bytes, not the node's reply, so the
	// returned outpoint is correct even if the broadcast response is lost.
	signedTx, err := elements.DeserializeTx(mustHexBytes(signed.Hex))
	if err != nil {
		return nil, err
	}
	txid := signedTx.TxID()
	if _, err := s.wallet.SendRawTransaction(signed.Hex); err != nil {
		return nil, err
	}
	s.st.AppendLog("consolidate", map[string]any{
		"txid": txid, "inputs": len(coins), "explicit_atoms": explicitSats, "dust_reserve": dustReserve(fee),
		"fee_asset": asset, "fee_atoms": fee,
	})
	return &feeCoin{txid: txid, vout: 0, sats: explicitSats, asset: asset, fee: fee}, nil
}

// handleConsolidate is the manual trigger: sweep blinded fee-asset change now.
func (s *Server) handleConsolidate(w http.ResponseWriter, r *http.Request) {
	rates, err := s.feeCandidates()
	if err != nil {
		httpErr(w, feeStatus(err), "consolidate: %v", err)
		return
	}
	coin, err := s.consolidateBlindedFees(rates, 0)
	if err != nil {
		httpErr(w, 502, "consolidate: %v", err)
		return
	}
	if coin == nil {
		httpErr(w, 409, "nothing to consolidate: no blinded coins of an asset the node accepts for fees (or their total cannot yield an explicit coin)")
		return
	}
	httpJSON(w, map[string]any{"txid": coin.txid, "explicit_atoms": coin.sats, "asset": coin.asset})
}
