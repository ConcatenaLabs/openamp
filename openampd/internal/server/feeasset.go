package server

import (
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/ConcatenaLabs/openamp/openampd/internal/store"
)

// The fee asset of a transaction this server funds.
//
// Sequentia's fee market is open: a transaction pays its fee in exactly one
// asset, which each node values at broadcast through its own exchange-rate
// table (getfeeexchangerates), and no asset is the default or a fallback.
// openampd chooses the fee asset of every transaction it funds by the rule
// every Sequentia wallet uses:
//
//  1. the asset the transaction moves, when the node accepts it for fees;
//  2. otherwise, among the assets the node accepts, the one whose largest
//     explicit coin in this server's wallet covers the most fees: the coin's
//     atoms valued at the node's rate, so the coin worth most in the node's
//     reference unit wins. No asset is preferred for what it is, the policy
//     asset included; a tie goes to the lower asset id, which says nothing
//     about either asset.
//
// Every asset openampd moves is a restricted asset, its reissuance token or a
// verifier asset, and none of them may ever pay a fee (Rule 1), so step 1
// never applies here and those assets are never candidates in step 2 either,
// even on a node that would accept one.
//
// -feeasset, where an operator sets it, is the operator's own choice and the
// only asset used; openampd refuses to start when the node does not accept
// it, and refuses a transaction when the node has stopped accepting it since.
//
// The fee itself, -feesats, is a value in the node's reference unit (the unit
// its exchange rates are quoted in, where a rate of 1e8 values one whole coin
// at one reference unit), so the fee is worth the same whichever asset pays
// it: ceil(feesats * 1e8 / rate) atoms of the chosen asset.

// feeCoin is the explicit wallet coin a transaction's fee comes out of, the
// asset it is in, and the fee that transaction pays, in atoms of that asset.
type feeCoin struct {
	txid  string
	vout  uint32
	sats  uint64 // the coin's atoms
	asset string // display hex of the fee asset
	fee   uint64 // the fee, in atoms of asset
}

// NoFeeCoin is the refusal when no coin of an accepted asset can pay: the
// caller answers 503 with its line.
type NoFeeCoin struct{ Reason string }

func (e *NoFeeCoin) Error() string { return e.Reason }

// feeStatus is the HTTP status for an error out of the fee picker.
func feeStatus(err error) int {
	if _, ok := err.(*NoFeeCoin); ok {
		return 503
	}
	return 502
}

// FeeRates reads a node's fee exchange-rate table, by lowercase asset id; an
// asset with no positive rate is not accepted and is left out. The node keys
// an asset that has a label (the policy asset's is "bitcoin") by the label, so
// labels are resolved to ids through dumpassetlabels.
func FeeRates(call func(out any, method string, params ...any) error) (map[string]uint64, error) {
	var raw map[string]json.Number
	if err := call(&raw, "getfeeexchangerates"); err != nil {
		return nil, fmt.Errorf("getfeeexchangerates: %w", err)
	}
	var labels map[string]string
	out := make(map[string]uint64, len(raw))
	for a, r := range raw {
		n, ok := new(big.Int).SetString(r.String(), 10)
		if !ok || n.Sign() <= 0 || !n.IsUint64() {
			continue
		}
		id := strings.ToLower(a)
		if !isAssetHex(id) {
			if labels == nil {
				if err := call(&labels, "dumpassetlabels"); err != nil {
					return nil, fmt.Errorf("dumpassetlabels (the rate table names %q): %w", a, err)
				}
			}
			id = strings.ToLower(labels[a])
			if !isAssetHex(id) {
				continue // a label the node cannot resolve names no coin
			}
		}
		out[id] = n.Uint64()
	}
	return out, nil
}

func isAssetHex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// feeAtomsAt is the fee, worth feeValue in the reference unit, in atoms of an
// asset the node rates at `rate`: ceil(feeValue * 1e8 / rate).
func feeAtomsAt(feeValue, rate uint64) (uint64, bool) {
	if rate == 0 {
		return 0, false
	}
	n := new(big.Int).Mul(new(big.Int).SetUint64(feeValue), big.NewInt(1e8))
	r := new(big.Int).SetUint64(rate)
	n.Add(n, new(big.Int).Sub(r, big.NewInt(1)))
	n.Quo(n, r)
	if !n.IsUint64() {
		return 0, false
	}
	return n.Uint64(), true
}

// restrictedIDs is every asset this server moves, which no fee may be paid
// in: each restricted asset, its reissuance token, and a network-enforced
// asset's verifier asset.
func (s *Server) restrictedIDs() map[string]bool {
	out := map[string]bool{}
	if s.st == nil {
		return out
	}
	s.st.View(func(st *store.State) {
		for id, a := range st.Assets {
			out[strings.ToLower(id)] = true
			if a.Token != "" {
				out[strings.ToLower(a.Token)] = true
			}
			if a.Damp != nil && a.Damp.VerifierAsset != "" {
				out[strings.ToLower(a.Damp.VerifierAsset)] = true
				if a.Damp.VerifierToken != nil && a.Damp.VerifierToken.Token != "" {
					out[strings.ToLower(a.Damp.VerifierToken.Token)] = true
				}
			}
		}
	})
	return out
}

// feeCandidates is the node's rate for every asset this server may pay a fee
// in now: the operator's -feeasset alone when set, else every asset the node
// accepts that is not one this server moves.
func (s *Server) feeCandidates() (map[string]uint64, error) {
	rates, err := FeeRates(s.node.Call)
	if err != nil {
		return nil, err
	}
	if s.cfg.FeeAsset != "" {
		fa := strings.ToLower(s.cfg.FeeAsset)
		if rates[fa] == 0 {
			return nil, &NoFeeCoin{Reason: fmt.Sprintf(
				"the fee asset this server is set to pay in (-feeasset %s) is not one the node accepts for fees now", fa)}
		}
		if s.restrictedIDs()[fa] {
			return nil, &NoFeeCoin{Reason: fmt.Sprintf(
				"the fee asset this server is set to pay in (-feeasset %s) is an asset it moves, which never pays a fee", fa)}
		}
		return map[string]uint64{fa: rates[fa]}, nil
	}
	never := s.restrictedIDs()
	out := map[string]uint64{}
	for a, r := range rates {
		if !never[a] {
			out[a] = r
		}
	}
	if len(out) == 0 {
		return nil, &NoFeeCoin{Reason: "the node accepts no asset for fees that this server may pay in, so it can fund no transaction"}
	}
	return out, nil
}

// feeIn is the fee, in atoms of `asset`, for a transaction whose fee coin is
// fixed already (phase 2 of a network-enforced issuance spends phase 1's
// change): refused when that asset is not one this server may pay in now.
func (s *Server) feeIn(asset string) (uint64, error) {
	rates, err := s.feeCandidates()
	if err != nil {
		return 0, err
	}
	a := strings.ToLower(asset)
	fee, ok := feeAtomsAt(s.cfg.FeeSats, rates[a])
	if !ok {
		return 0, &NoFeeCoin{Reason: fmt.Sprintf("%s, the asset of this transaction's fee coin, is not one the node accepts for fees now", a)}
	}
	return fee, nil
}

// pickFeeCoins applies the rule to the candidates' rates and a wallet's
// explicit coins: every coin of an accepted asset, each with the fee in its
// asset, the coin worth most at the node's rate first (a tie goes to the lower
// asset id). The first coin is the rule's choice: the largest coin of the
// asset whose largest coin covers the most fees. The caller takes the first
// that is still unspent and covers the fees it needs, so a coin spent since
// the wallet listed it gives way to the next.
func pickFeeCoins(feeValue uint64, rates map[string]uint64, coins []feeCoin) []feeCoin {
	out := make([]feeCoin, 0, len(coins))
	for _, c := range coins {
		c.asset = strings.ToLower(c.asset)
		if rates[c.asset] == 0 || c.sats == 0 {
			continue
		}
		fee, ok := feeAtomsAt(feeValue, rates[c.asset])
		if !ok {
			continue
		}
		c.fee = fee
		out = append(out, c)
	}
	worth := func(c feeCoin) *big.Int {
		return new(big.Int).Mul(new(big.Int).SetUint64(c.sats), new(big.Int).SetUint64(rates[c.asset]))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if d := worth(out[i]).Cmp(worth(out[j])); d != 0 {
			return d > 0
		}
		return out[i].asset < out[j].asset
	})
	return out
}

// noFeeCoinLine says why nothing can pay, naming the accepted assets.
func noFeeCoinLine(rates map[string]uint64, mult uint64) *NoFeeCoin {
	accepted := make([]string, 0, len(rates))
	for a := range rates {
		accepted = append(accepted, a)
	}
	sort.Strings(accepted)
	return &NoFeeCoin{Reason: fmt.Sprintf(
		"no fee coin: this server's wallet holds no explicit coin worth more than %d fees in an asset the node accepts for fees (%s)",
		mult, strings.Join(accepted, ", "))}
}
