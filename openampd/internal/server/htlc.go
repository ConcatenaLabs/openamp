package server

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/ConcatenaLabs/openamp/openampd/internal/elements"
	"github.com/ConcatenaLabs/openamp/openampd/internal/store"
)

// Swap HTLCs: the Sequentia side of a restricted asset traded for on-chain
// BTC (elements/htlc.go has the scripts). The seller locks its coin in an
// HTLC for one registered buyer, through POST /v1/cosign with the output
// named in htlc_outputs: the HTLC stays the seller's coin for every rule,
// and the buyer must be able to receive it now. The buyer claims it, also
// through POST /v1/cosign, with the HTLC named in htlc_inputs: that claim
// is the transfer seller -> buyer, judged then by every rule, and this server
// co-signs it, again on request with a different fee, until the cut-off an
// hour before T_seq. After T_seq anyone sends the coin home to the seller's
// enclave by the keyless refund leaf, which needs nothing from this server.

const (
	// claimCutoff: no claim is co-signed later than this before T_seq. The
	// refund is keyless, so a claim revealed at the last moment could be beaten
	// by it; an hour leaves a claim broadcast at the cut-off at least 40 blocks
	// to confirm even at a 90-second slot, before the median time past (which
	// the refund's lock is judged by) can pass T_seq.
	claimCutoff = time.Hour
	// minHTLCWindow: at the lock, T_seq must leave the buyer at least an hour
	// to claim before the cut-off.
	minHTLCWindow = 2 * time.Hour
	// maxHTLCWindow bounds how long a seller's coin can be tied up.
	maxHTLCWindow = 7 * 24 * time.Hour
)

type htlcOutput struct {
	Output   int    `json:"output"`
	BuyerAID string `json:"buyer_aid"`
	Hash     string `json:"hash"`
	TSeq     uint32 `json:"t_seq"`
}

type htlcInput struct {
	Input int `json:"input"`
}

// now is the later of this server's clock and the chain's median time past:
// a deadline has passed when either says so.
func (s *Server) now() time.Time {
	t := time.Now()
	if s.clock != nil {
		t = s.clock()
	}
	if s.node != nil {
		var info struct {
			MedianTime int64 `json:"mediantime"`
		}
		if err := s.node.Call(&info, "getblockchaininfo"); err == nil && info.MedianTime > 0 {
			if m := time.Unix(info.MedianTime, 0); m.After(t) {
				t = m
			}
		}
	}
	return t
}

// htlcTree rebuilds an HTLC from its terms and the asset's record.
func (s *Server) htlcTree(asset *store.Asset, seller, buyer *store.User, hash [32]byte, tSeq uint32, value uint64) (*elements.TapTree, error) {
	sellerTree, err := s.treeFor(seller, asset)
	if err != nil {
		return nil, err
	}
	var assetID [32]byte
	copy(assetID[:], explicitAssetCommit(asset.ID)[1:])
	terms := elements.SwapHTLCTerms{
		Hash:          hash,
		BuyerX:        elements.MustHex32(buyer.Pubkeys[0]),
		PolicyX:       elements.MustHex32(asset.PolicyPub),
		TSeq:          tSeq,
		SellerProgram: sellerTree.OutputKey,
		Asset:         assetID,
		Value:         value,
	}
	if asset.Clawback {
		x := elements.MustHex32(asset.IssuerPub)
		terms.IssuerX = &x
	}
	return elements.SwapHTLCTree(terms)
}

func parseHash(h string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 32 {
		return out, fmt.Errorf("hash must be 64 hex characters")
	}
	copy(out[:], b)
	return out, nil
}

// admitHTLCOutputs checks each named output is the HTLC its terms describe,
// for a registered buyer who could receive it now, and admits it as the
// sender's own coin. It returns the admitted scripts and the records to store
// once the lock is co-signed.
func (s *Server) admitHTLCOutputs(tx *elements.Tx, asset *store.Asset, sender *store.User, outs []htlcOutput) (map[string]*store.User, []*store.HTLC, error) {
	admitted := map[string]*store.User{}
	var recs []*store.HTLC
	now := s.now()
	assetCommit := hex.EncodeToString(explicitAssetCommit(asset.ID))
	var height int64
	s.st.View(func(st *store.State) { height = st.Height })
	for _, o := range outs {
		if o.Output < 0 || o.Output >= len(tx.Out) {
			return nil, nil, refuseCode("htlc", "HTLC output %d out of range", o.Output)
		}
		out := tx.Out[o.Output]
		if hex.EncodeToString(out.Asset) != assetCommit {
			return nil, nil, refuseCode("htlc", "HTLC output %d does not carry this asset", o.Output)
		}
		value, ok := elements.ExplicitValueAmount(out.Value)
		if !ok || value == 0 {
			return nil, nil, refuseCode("htlc", "HTLC output %d must carry an explicit, nonzero amount", o.Output)
		}
		hash, err := parseHash(o.Hash)
		if err != nil {
			return nil, nil, refuseCode("htlc", "HTLC output %d: %v", o.Output, err)
		}
		if o.TSeq < elements.MinTimeLock {
			return nil, nil, refuseCode("htlc", "HTLC output %d: t_seq %d is a height; a swap's locks are times", o.Output, o.TSeq)
		}
		tSeq := time.Unix(int64(o.TSeq), 0)
		if tSeq.Before(now.Add(minHTLCWindow)) || tSeq.After(now.Add(maxHTLCWindow)) {
			return nil, nil, refuseCode("htlc", "HTLC output %d: t_seq must be between %s and %s from now", o.Output, minHTLCWindow, maxHTLCWindow)
		}
		var buyer *store.User
		s.st.View(func(st *store.State) {
			if u, ok := st.Users[o.BuyerAID]; ok {
				cp := *u
				buyer = &cp
			}
		})
		if buyer == nil {
			return nil, nil, refuseCode("unregistered", "HTLC output %d: the buyer is not registered", o.Output)
		}
		if buyer.AID == sender.AID {
			return nil, nil, refuseCode("htlc", "HTLC output %d: the buyer is the seller", o.Output)
		}
		if buyer.Frozen && buyer.AID != asset.IssuerAID {
			return nil, nil, refuseCode("frozen", "HTLC output %d: the buyer is frozen", o.Output)
		}
		tree, err := s.htlcTree(asset, sender, buyer, hash, o.TSeq, value)
		if err != nil {
			return nil, nil, err
		}
		spk := hex.EncodeToString(tree.ScriptPubKey())
		if spk != hex.EncodeToString(out.ScriptPubKey) {
			return nil, nil, refuseCode("htlc", "output %d is not the HTLC its terms describe", o.Output)
		}
		// The buyer must be able to receive the coin now; otherwise the seller
		// would lock a coin nobody can claim, and the buyer's bitcoin would wait
		// for nothing. The claim is judged again, in full, when it comes.
		if err := s.checkRules(asset, sender, map[string]uint64{buyer.AID: value}, 0, height); err != nil {
			return nil, nil, err
		}
		admitted[spk] = sender
		recs = append(recs, &store.HTLC{
			SPK: spk, Asset: asset.ID, SellerAID: sender.AID, BuyerAID: buyer.AID,
			Hash: hex.EncodeToString(hash[:]), TSeq: o.TSeq, Value: value, Vout: uint32(o.Output),
		})
	}
	return admitted, recs, nil
}

// htlcClaim checks a claim: one HTLC of this asset, owned by the sender,
// spent before the cut-off, its whole amount paid to its buyer's enclave and
// nowhere else. It returns the HTLC, its rebuilt tree and the input index.
func (s *Server) htlcClaim(tx *elements.Tx, spent []*elements.SpentOutput, asset *store.Asset, sender *store.User, ins []htlcInput) (*store.HTLC, *elements.TapTree, int, error) {
	if len(ins) != 1 {
		return nil, nil, 0, refuseCode("htlc", "a claim spends exactly one HTLC")
	}
	idx := ins[0].Input
	if idx < 0 || idx >= len(tx.In) {
		return nil, nil, 0, refuseCode("htlc", "HTLC input %d out of range", idx)
	}
	var rec *store.HTLC
	var buyer *store.User
	spk := hex.EncodeToString(spent[idx].ScriptPubKey)
	s.st.View(func(st *store.State) {
		if e, ok := st.HTLCs[spk]; ok {
			cp := *e
			rec = &cp
			if u, ok := st.Users[e.BuyerAID]; ok {
				cu := *u
				buyer = &cu
			}
		}
	})
	if rec == nil || rec.Asset != asset.ID {
		return nil, nil, 0, refuseCode("htlc", "input %d is not an HTLC of this asset", idx)
	}
	if rec.SellerAID != sender.AID {
		return nil, nil, 0, refuseCode("htlc", "input %d is not the sender's HTLC", idx)
	}
	if buyer == nil {
		return nil, nil, 0, refuseCode("unregistered", "the HTLC's buyer is no longer registered")
	}
	// A claim must be valid now: with a lock time it could be mined only
	// when the keyless refund is valid too, and lose to it with the secret out
	// (#67).
	if tx.LockTime != 0 {
		return nil, nil, 0, refuseCode("htlc", "a claim carries no lock time: it must be final now")
	}
	for i, in := range tx.In {
		if in.Sequence != 0xffffffff {
			return nil, nil, 0, refuseCode("htlc", "input %d of a claim is not final", i)
		}
	}
	var mined bool
	op := outpointString(tx.In[idx].Prevout)
	s.st.View(func(st *store.State) {
		for _, t := range st.Transfers {
			if t.Kind == "htlc-claim" && t.ID == op && t.Height >= 0 {
				mined = true
			}
		}
	})
	if mined {
		return nil, nil, 0, refuseCode("htlc", "this HTLC was already claimed")
	}
	cutoff := time.Unix(int64(rec.TSeq), 0).Add(-claimCutoff)
	if !s.now().Before(cutoff) {
		return nil, nil, 0, refuseCode("claim_cutoff", "the claim cut-off has passed (%s); the HTLC goes home to its seller at t_seq", cutoff.UTC().Format(time.RFC3339))
	}
	hash, _ := parseHash(rec.Hash)
	tree, err := s.htlcTree(asset, sender, buyer, hash, rec.TSeq, rec.Value)
	if err != nil {
		return nil, nil, 0, err
	}
	if hex.EncodeToString(tree.ScriptPubKey()) != spk {
		return nil, nil, 0, fmt.Errorf("HTLC %s no longer rebuilds from its record", spk)
	}
	buyerTree, err := s.treeFor(buyer, asset)
	if err != nil {
		return nil, nil, 0, err
	}
	// Every output plain: a proof or a nonce on an explicit output makes the
	// node refuse the claim (bad-txns-in-ne-out), and a co-sign of a claim
	// that cannot be mined only puts the secret where it does nobody good
	// (PV5 S17).
	tx.NormalizeWitness()
	for i, out := range tx.Out {
		if !tx.OutWit[i].IsNull() || !isNullNonce(out.Nonce) {
			return nil, nil, 0, refuseCode("htlc", "output %d of a claim carries a proof or a nonce: every output of a claim is plain", i)
		}
	}
	assetCommit := hex.EncodeToString(explicitAssetCommit(asset.ID))
	buyerSpk := hex.EncodeToString(buyerTree.ScriptPubKey())
	paid := 0
	for i, out := range tx.Out {
		if hex.EncodeToString(out.Asset) != assetCommit {
			continue
		}
		v, _ := elements.ExplicitValueAmount(out.Value)
		if hex.EncodeToString(out.ScriptPubKey) != buyerSpk || v != rec.Value {
			return nil, nil, 0, refuseCode("htlc", "output %d: a claim pays the HTLC's whole amount to its buyer's enclave and nothing else", i)
		}
		paid++
	}
	if paid != 1 {
		return nil, nil, 0, refuseCode("htlc", "a claim pays the HTLC to its buyer's enclave in exactly one output")
	}
	for i := range tx.In {
		if i != idx && hex.EncodeToString(spent[i].Asset) == assetCommit {
			return nil, nil, 0, refuseCode("htlc", "input %d: a claim spends the HTLC and no other coin of the asset", i)
		}
	}
	return rec, tree, idx, nil
}

// handleHTLCClaim co-signs a buyer's claim of an HTLC: the claim leaf's
// policy signature, never a broadcast, because the buyer adds the secret. A
// later request for the same HTLC (a higher fee, after a stuck claim) is
// judged without the earlier one's velocity record, and replaces it rather
// than adding a second. The record stops counting at T_seq unless mined.
func (s *Server) handleHTLCClaim(w http.ResponseWriter, tx *elements.Tx, spent []*elements.SpentOutput, asset *store.Asset, sender *store.User, ins []htlcInput, dry bool) {
	rec, tree, idx, err := s.htlcClaim(tx, spent, asset, sender, ins)
	if err == nil {
		err = s.checkTransferExcept(tx, asset, sender, map[string]uint64{}, nil, outpointString(tx.In[idx].Prevout))
	}
	if err != nil {
		if pr, isRefusal := err.(*PolicyRefusal); isRefusal {
			if !dry {
				logRefusal("htlc-claim", s.st, map[string]any{"seller": sender.AID, "asset": asset.ID, "reason": pr.Reason})
			}
			httpErr(w, 403, "%v", pr)
			return
		}
		httpErr(w, 502, "%v", err)
		return
	}
	if dry {
		httpJSON(w, map[string]any{"ok": true, "atoms": rec.Value, "cutoff": time.Unix(int64(rec.TSeq), 0).Add(-claimCutoff).Unix()})
		return
	}
	leaf := tree.Leaves["claim"].Script
	control, _ := tree.ControlBlock("claim")
	txid := tx.TxID()
	sh, err := elements.TaprootSighash(tx, spent, elements.SighashDefault, s.genesis, idx, leaf)
	if err != nil {
		httpErr(w, 500, "sighash: %v", err)
		return
	}
	sig, err := s.signer.SignPolicy(asset.ID, sh, PolicyContext{Action: "htlc-claim", AID: sender.AID, TxID: txid, InputIndex: idx})
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	outpoint := outpointString(tx.In[idx].Prevout)
	if err := s.st.Update(func(st *store.State) error {
		// A re-claim replaces the same HTLC's unmined claim, never a mined
		// one, and never another HTLC's: two HTLCs of the same terms share a
		// script, not an outpoint (#65).
		kept := st.Transfers[:0]
		for _, t := range st.Transfers {
			if !(t.Kind == "htlc-claim" && t.ID == outpoint && t.Height < 0) {
				kept = append(kept, t)
			}
		}
		st.Transfers = append(kept, store.TransferRecord{
			Txid: txid, Asset: asset.ID, SenderAID: sender.AID, Atoms: rec.Value, Height: -1,
			Kind: "htlc-claim", ID: outpoint, Inputs: txInputs(tx),
		})
		return nil
	}); err != nil {
		httpErr(w, 500, "record the claim: %v", err)
		return
	}
	s.st.AppendLog("htlc-claim", map[string]any{"txid": txid, "seller": rec.SellerAID, "buyer": rec.BuyerAID,
		"asset": asset.ID, "atoms": rec.Value, "htlc": rec.SPK})
	cutoff := time.Unix(int64(rec.TSeq), 0).Add(-claimCutoff)
	httpJSON(w, map[string]any{
		"sigs": []map[string]any{{
			"input": idx, "sighash": hex.EncodeToString(sh[:]), "policy_sig": hex.EncodeToString(sig),
			"leaf": hex.EncodeToString(leaf), "control": hex.EncodeToString(control),
		}},
		"cutoff": cutoff.Unix(),
	})
}

// isNullNonce: an output's nonce is absent (one zero byte, or empty).
func isNullNonce(n []byte) bool { return len(n) == 0 || (len(n) == 1 && n[0] == 0) }
