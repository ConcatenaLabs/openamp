package server

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/ConcatenaLabs/openamp/openampd/internal/elements"
	"github.com/ConcatenaLabs/openamp/openampd/internal/store"
)

// Gated orders: a holder's resting offer to sell a restricted asset on the
// chain (elements/gated.go has the scripts). The maker places it through
// POST /v1/cosign with the output named in order_outputs, as its own move: the
// order stays the maker's coin for every rule. A taker fills it through the
// same endpoint with the order named in order_inputs and "broadcast": true:
// that fill is the transfer maker -> taker, judged then by every rule, and this
// server co-signs it and broadcasts it in one step, so its signature never
// outlives the decision (a freeze, a rule change, the expiry). No fill is
// co-signed at or after the expiry; after it anyone sends the coin home to the
// maker's enclave by the keyless refund leaf.

const (
	minOrderLife = time.Hour
	maxOrderLife = 30 * 24 * time.Hour
)

type orderOutput struct {
	Output int    `json:"output"`
	Fill   string `json:"fill"`   // the SeqDEX fill covenant the order wraps (hex)
	Expiry uint32 `json:"expiry"` // Unix time
}

type orderInput struct {
	Input int `json:"input"`
}

// orderTree rebuilds a gated order from its terms and the asset's record.
func (s *Server) orderTree(asset *store.Asset, maker *store.User, fill []byte, expiry uint32) (*elements.TapTree, error) {
	makerTree, err := s.treeFor(maker, asset)
	if err != nil {
		return nil, err
	}
	var assetID [32]byte
	copy(assetID[:], explicitAssetCommit(asset.ID)[1:])
	terms := elements.GatedOrderTerms{
		PolicyX:      elements.MustHex32(asset.PolicyPub),
		Fill:         fill,
		Expiry:       expiry,
		MakerProgram: makerTree.OutputKey,
		Asset:        assetID,
	}
	if asset.Clawback {
		x := elements.MustHex32(asset.IssuerPub)
		terms.IssuerX = &x
	}
	return elements.GatedOrderTree(terms)
}

// admitOrderOutputs checks each named output is the gated order its terms
// describe and admits it as the sender's own coin. It returns the admitted
// scripts and the records to store once the placement is co-signed.
func (s *Server) admitOrderOutputs(tx *elements.Tx, asset *store.Asset, sender *store.User, outs []orderOutput) (map[string]*store.User, []*store.GatedOrder, error) {
	admitted := map[string]*store.User{}
	var recs []*store.GatedOrder
	now := s.now()
	assetCommit := hex.EncodeToString(explicitAssetCommit(asset.ID))
	for _, o := range outs {
		if o.Output < 0 || o.Output >= len(tx.Out) {
			return nil, nil, refuseCode("order", "order output %d out of range", o.Output)
		}
		out := tx.Out[o.Output]
		if hex.EncodeToString(out.Asset) != assetCommit {
			return nil, nil, refuseCode("order", "order output %d does not carry this asset", o.Output)
		}
		if v, ok := elements.ExplicitValueAmount(out.Value); !ok || v == 0 {
			return nil, nil, refuseCode("order", "order output %d must carry an explicit, nonzero amount", o.Output)
		}
		fill, err := hex.DecodeString(o.Fill)
		if err != nil || len(fill) == 0 || len(fill) > elements.GatedFillMax {
			return nil, nil, refuseCode("order", "order output %d: fill must be 1 to %d bytes of hex", o.Output, elements.GatedFillMax)
		}
		if o.Expiry < elements.MinTimeLock {
			return nil, nil, refuseCode("order", "order output %d: expiry %d is a height; an order's expiry is a time", o.Output, o.Expiry)
		}
		exp := time.Unix(int64(o.Expiry), 0)
		if exp.Before(now.Add(minOrderLife)) || exp.After(now.Add(maxOrderLife)) {
			return nil, nil, refuseCode("order", "order output %d: expiry must be between %s and %s from now", o.Output, minOrderLife, maxOrderLife)
		}
		tree, err := s.orderTree(asset, sender, fill, o.Expiry)
		if err != nil {
			return nil, nil, err
		}
		spk := hex.EncodeToString(tree.ScriptPubKey())
		if spk != hex.EncodeToString(out.ScriptPubKey) {
			return nil, nil, refuseCode("order", "output %d is not the gated order its terms describe", o.Output)
		}
		admitted[spk] = sender
		recs = append(recs, &store.GatedOrder{SPK: spk, Asset: asset.ID, MakerAID: sender.AID, Fill: o.Fill,
			Expiry: o.Expiry, Vout: uint32(o.Output)})
	}
	return admitted, recs, nil
}

// handleOrderFill judges a fill of one gated order and, unless dry, co-signs
// its order input and broadcasts the transaction. Every other input must
// arrive signed.
func (s *Server) handleOrderFill(w http.ResponseWriter, tx *elements.Tx, spent []*elements.SpentOutput, asset *store.Asset,
	sender *store.User, ins []orderInput, dry, broadcast bool) {
	refuse := func(err error) {
		if pr, isRefusal := err.(*PolicyRefusal); isRefusal {
			if !dry {
				logRefusal("order-fill", s.st, map[string]any{"maker": sender.AID, "asset": asset.ID, "reason": pr.Reason})
			}
			httpErr(w, 403, "%v", pr)
			return
		}
		httpErr(w, 502, "%v", err)
	}
	if !dry && !broadcast {
		httpErr(w, 400, "an order is filled only with \"broadcast\": true: this server co-signs a fill and broadcasts it in one step")
		return
	}
	if len(ins) != 1 {
		refuse(refuseCode("order", "a fill spends exactly one gated order"))
		return
	}
	idx := ins[0].Input
	if idx < 0 || idx >= len(tx.In) {
		refuse(refuseCode("order", "order input %d out of range", idx))
		return
	}
	spk := hex.EncodeToString(spent[idx].ScriptPubKey)
	var rec *store.GatedOrder
	s.st.View(func(st *store.State) {
		if o, ok := st.GatedOrders[spk]; ok {
			cp := *o
			rec = &cp
		}
	})
	if rec == nil || rec.Asset != asset.ID {
		refuse(refuseCode("order", "input %d is not a gated order of this asset", idx))
		return
	}
	if rec.MakerAID != sender.AID {
		refuse(refuseCode("order", "input %d is not the sender's order", idx))
		return
	}
	if !s.now().Before(time.Unix(int64(rec.Expiry), 0)) {
		refuse(refuseCode("expired", "the order expired at %s; it goes home to its maker", time.Unix(int64(rec.Expiry), 0).UTC().Format(time.RFC3339)))
		return
	}
	fill, _ := hex.DecodeString(rec.Fill)
	tree, err := s.orderTree(asset, sender, fill, rec.Expiry)
	if err != nil {
		refuse(err)
		return
	}
	if hex.EncodeToString(tree.ScriptPubKey()) != spk {
		refuse(fmt.Errorf("order %s no longer rebuilds from its record", spk))
		return
	}
	assetCommit := hex.EncodeToString(explicitAssetCommit(asset.ID))
	for i := range tx.In {
		if i != idx && hex.EncodeToString(spent[i].Asset) == assetCommit {
			refuse(refuseCode("order", "input %d: a fill spends the order and no other coin of the asset", i))
			return
		}
	}
	// The remainder at the order's own script stays the maker's.
	atomsOut := map[string]uint64{}
	if err := s.checkTransferAdmitting(tx, asset, sender, atomsOut, map[string]*store.User{spk: sender}); err != nil {
		refuse(err)
		return
	}
	var sent uint64
	for _, a := range atomsOut {
		sent += a
	}
	if dry {
		httpJSON(w, map[string]any{"ok": true, "atoms": sent})
		return
	}
	leaf := tree.Leaves["fill"].Script
	control, _ := tree.ControlBlock("fill")
	sh, err := elements.TaprootSighash(tx, spent, elements.SighashDefault, s.genesis, idx, leaf)
	if err != nil {
		httpErr(w, 500, "sighash: %v", err)
		return
	}
	txid := tx.TxID()
	sig, err := s.signer.SignPolicy(asset.ID, sh, PolicyContext{Action: "order-fill", AID: sender.AID, TxID: txid, InputIndex: idx})
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	for len(tx.InWit) < len(tx.In) {
		tx.InWit = append(tx.InWit, &elements.TxInWitness{})
	}
	tx.InWit[idx].ScriptWitness = [][]byte{sig, leaf, control}
	signed := hex.EncodeToString(tx.Serialize())
	if err := s.mempoolGate("order-fill", signed, map[string]any{"maker": sender.AID}); err != nil {
		httpErr(w, 409, "%v", err)
		return
	}
	if _, err := s.wallet.SendRawTransaction(signed); err != nil {
		httpErr(w, 409, "%v", err)
		return
	}
	s.st.Update(func(st *store.State) error {
		st.Transfers = append(st.Transfers, store.TransferRecord{
			Txid: txid, Asset: asset.ID, SenderAID: sender.AID, Atoms: sent, Height: -1,
			Expires: time.Now().Add(pendingTTL).Unix(), Kind: "order-fill", ID: spk,
		})
		return nil
	})
	s.st.AppendLog("order-fill", map[string]any{"txid": txid, "maker": sender.AID, "asset": asset.ID, "atoms": sent, "order": spk})
	httpJSON(w, map[string]any{"txid": txid})
}
