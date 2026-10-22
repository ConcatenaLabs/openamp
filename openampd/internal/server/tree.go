package server

// An asset's tree: holdings of a co-signed restricted asset may sit in
// enclave-1 leaves of an operator the issuer names, reassigned off the chain
// under the same rules as an on-chain transfer.
//
// An enclave-1 leaf is two-party (its owner and the tree's operator) with an
// exit that pays only its holder's enclave, in full, and, where the asset
// elected clawback, the enclave's own claw leaf. The operator's signer
// co-signs a leaf's spend only beside this server's signature over the same
// message, so every reassignment passes the policy here. This server never
// builds or parses a leaf itself: the scripts and the messages come from
// arca-enclave, a tool built from the arca repository (-arcaenclave), so what
// is checked here is what arca builds.
//
//	POST /v1/issuer/tree                       enable an asset's tree, naming its operator
//	POST /v1/cosign  + tree_outputs            admit a board of the asset's tree (an enclave-1 leaf of a registered holder)
//	POST /v1/issuer/tree/transfer              approve a reassignment: the rules, the register, one signature per message
//	POST /v1/issuer/tree/transfer/{id}/drop    give a reassignment's inputs back before it was used
//	POST /v1/issuer/tree/clawback              the policy half of a claw leaf's spend, where the asset elected clawback
//	POST /v1/tree/leaves/{salt}/exited         close a leaf whose holder took it home to its enclave

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ConcatenaLabs/openamp/openampd/internal/elements"
	"github.com/ConcatenaLabs/openamp/openampd/internal/store"
)

// noTreeTool is the refusal of every tree call on a server without the tool.
const noTreeTool = "this policy server runs no tree tool (-arcaenclave): it cannot check a leaf of an asset's tree, so it co-signs none"

// treeCosignTag is the tag of the message this server signs beside the tree
// operator: SHA256(T ‖ T ‖ digest), T = SHA256("OpenAMP/tree-cosign"), digest
// the rebindable message's own SHA256. The tag keeps these signatures apart
// from every taproot signature hash the same policy key signs on the chain.
const treeCosignTag = "OpenAMP/tree-cosign"

// TreeTool runs arca-enclave: cmd is "board" or "transfer", stdin the request.
// A refusal of the tool's comes back as a *TreeToolRefusal.
type TreeTool interface {
	Run(cmd string, stdin []byte) ([]byte, error)
}

// TreeToolRefusal is the tool's own refusal of a request: exit 1 with
// {"error": ...}. The request named something that is no leaf of this kind.
type TreeToolRefusal struct{ Reason string }

func (e *TreeToolRefusal) Error() string { return "arca-enclave: " + e.Reason }

type execTreeTool struct{ path string }

func (t execTreeTool) Run(cmd string, stdin []byte) ([]byte, error) {
	c := exec.Command(t.path, cmd)
	c.Stdin = bytes.NewReader(stdin)
	var out, errb bytes.Buffer
	c.Stdout, c.Stderr = &out, &errb
	if err := c.Run(); err != nil {
		var r struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(out.Bytes(), &r) == nil && r.Error != "" {
			return nil, &TreeToolRefusal{Reason: r.Error}
		}
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("arca-enclave %s failed: %s", cmd, msg)
	}
	return out.Bytes(), nil
}

// treeLock serializes the register's writes for one asset: two approvals
// spending one leaf must never both pass.
func (s *Server) treeLock(asset string) *sync.Mutex {
	m, _ := s.treeLocks.LoadOrStore(asset, &sync.Mutex{})
	return m.(*sync.Mutex)
}

func (s *Server) genesisDisplay() string {
	var b [32]byte
	for i := 0; i < 32; i++ {
		b[i] = s.genesis[31-i]
	}
	return hex.EncodeToString(b[:])
}

// treeCosignMessage is what the policy key signs for a rebindable digest.
func treeCosignMessage(digest [32]byte) [32]byte {
	t := sha256.Sum256([]byte(treeCosignTag))
	h := sha256.New()
	h.Write(t[:])
	h.Write(t[:])
	h.Write(digest[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// treeTermsOf is the terms an asset's tree leaves must carry.
func treeTermsOf(asset *store.Asset, operator string) store.TreeTerms {
	t := store.TreeTerms{Operator: strings.ToLower(operator), Policy: strings.ToLower(asset.PolicyPub)}
	if asset.Clawback {
		k := strings.ToLower(asset.IssuerPub)
		t.Clawback = &k
	}
	return t
}

// userByKey is the registered user whose active enclave key is key.
func userByKey(st *store.State, key string) *store.User {
	key = strings.ToLower(key)
	for _, u := range st.Users {
		if len(u.Pubkeys) > 0 && strings.ToLower(u.Pubkeys[0]) == key {
			cp := *u
			return &cp
		}
	}
	return nil
}

func sameKey(a *string, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return strings.EqualFold(*a, *b)
}

func keyOrNone(k *string) string {
	if k == nil {
		return "none"
	}
	return *k
}

// treeErr answers an error from the tree path: a refusal of the tool's is a
// request naming no such leaf (400), a policy refusal 403, anything else 502.
func treeErr(w http.ResponseWriter, err error) {
	var tr *TreeToolRefusal
	var pr *PolicyRefusal
	switch {
	case errors.As(err, &tr):
		httpErr(w, 400, "%v", tr)
	case errors.As(err, &pr):
		httpErr(w, 403, "%v", pr)
	default:
		httpErr(w, 502, "%v", err)
	}
}

// --- enabling ----------------------------------------------------------------

func (s *Server) handleTreeEnable(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Asset    string `json:"asset"`
		Operator string `json:"operator"`
	}
	if err := decodeBody(r, &req); err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	if s.treeTool == nil {
		httpErr(w, 501, noTreeTool)
		return
	}
	op := strings.ToLower(req.Operator)
	if !xonlyHex.MatchString(op) {
		httpErr(w, 400, "operator must be an x-only key, 64 hex characters")
		return
	}
	var terms store.TreeTerms
	code, err := 200, error(nil)
	err = s.st.Update(func(st *store.State) error {
		a, ok := st.Assets[req.Asset]
		if !ok {
			code = 404
			return fmt.Errorf("unknown asset %s", req.Asset)
		}
		if a.Enforcement == "damp" {
			code = 409
			return fmt.Errorf("asset %s is network-enforced: its holdings live in covenants this server does not co-sign, so it has no tree", a.ID)
		}
		if a.Tree != nil && a.Tree.Operator != op {
			for _, l := range st.TreeLeaves {
				if l.Asset == a.ID && (l.State == store.LeafLive || l.State == store.LeafBoarding) {
					code = 409
					return fmt.Errorf("asset %s's tree has leaves of operator %s still held: they name that operator's key, so the operator cannot change while any is", a.ID, a.Tree.Operator)
				}
			}
		}
		terms = treeTermsOf(a, op)
		a.Tree = &terms
		return nil
	})
	if err != nil {
		if code == 200 {
			code = 500
		}
		httpErr(w, code, "%v", err)
		return
	}
	s.st.AppendLog("tree_enable", map[string]any{"asset": req.Asset, "operator": terms.Operator,
		"policy": terms.Policy, "clawback": terms.Clawback})
	httpJSON(w, map[string]any{"asset": req.Asset, "tree": terms})
}

// --- admission ---------------------------------------------------------------

// treeOutput is one output of a co-signed transaction that the caller says is
// a board of the asset's tree, with the board's record.
type treeOutput struct {
	Output int    `json:"output"`
	Record string `json:"record"`
}

type toolBoard struct {
	Template         string  `json:"template"`
	ScriptPubKey     string  `json:"script_pubkey"`
	LeafScriptPubKey string  `json:"leaf_script_pubkey"`
	Asset            string  `json:"asset"`
	Value            string  `json:"value"`
	Holder           string  `json:"holder"`
	Policy           string  `json:"policy"`
	Clawback         *string `json:"clawback"`
	Operator         string  `json:"operator"`
	Genesis          string  `json:"genesis"`
	Salt             string  `json:"salt"`
	ClawControl      *string `json:"claw_control"`
	LeafClawControl  *string `json:"leaf_claw_control"`
}

func optHex(p *string) string {
	if p == nil {
		return ""
	}
	return strings.ToLower(*p)
}

// admitTreeOutputs checks each named output against its board record: the
// tool's reading of the record must be an enclave-1 board of the asset's tree
// (its policy key, its clawback election, its operator, this chain) whose
// output is exactly the transaction's, for a registered holder. It returns
// each admitted script with its holder, for the rules, and the leaves to
// register once the transaction is co-signed.
func (s *Server) admitTreeOutputs(tx *elements.Tx, asset *store.Asset, outs []treeOutput) (map[string]*store.User, []*store.TreeLeaf, error) {
	if s.treeTool == nil {
		return nil, nil, errNoTreeTool
	}
	if asset.Tree == nil {
		return nil, nil, refuse("asset %s has no tree: the issuer has not enabled one (POST /v1/issuer/tree)", asset.ID)
	}
	terms := *asset.Tree
	admitted := map[string]*store.User{}
	var leaves []*store.TreeLeaf
	seen := map[int]bool{}
	txid := tx.TxID()
	for _, o := range outs {
		if o.Output < 0 || o.Output >= len(tx.Out) {
			return nil, nil, refuse("tree output %d is not an output of the transaction", o.Output)
		}
		if seen[o.Output] {
			return nil, nil, refuse("tree output %d is named twice", o.Output)
		}
		seen[o.Output] = true
		in, _ := json.Marshal(map[string]string{"record": o.Record})
		raw, err := s.treeTool.Run("board", in)
		if err != nil {
			return nil, nil, err
		}
		var b toolBoard
		if err := json.Unmarshal(raw, &b); err != nil {
			return nil, nil, fmt.Errorf("arca-enclave board answered no board: %w", err)
		}
		out := tx.Out[o.Output]
		value, _ := strconv.ParseUint(b.Value, 10, 64)
		atoms, explicit := elements.ExplicitValueAmount(out.Value)
		switch {
		case b.Template != "enclave-1":
			return nil, nil, refuse("tree output %d: its record is a %s board, and a restricted asset's tree holds enclave-1 leaves only", o.Output, b.Template)
		case !strings.EqualFold(b.Asset, asset.ID):
			return nil, nil, refuse("tree output %d: its record is a board of asset %s, not %s", o.Output, b.Asset, asset.ID)
		case !strings.EqualFold(b.Genesis, s.genesisDisplay()):
			return nil, nil, refuse("tree output %d: its record is a board of the chain whose genesis is %s, not this one's", o.Output, b.Genesis)
		case !strings.EqualFold(b.Policy, terms.Policy):
			return nil, nil, refuse("tree output %d: its leaf names policy key %s, and the asset's is %s", o.Output, b.Policy, terms.Policy)
		case !sameKey(b.Clawback, terms.Clawback):
			return nil, nil, refuse("tree output %d: its leaf's clawback key is %s, and the asset's election is %s", o.Output, keyOrNone(b.Clawback), keyOrNone(terms.Clawback))
		case !strings.EqualFold(b.Operator, terms.Operator):
			return nil, nil, refuse("tree output %d: its leaf names operator %s, and the asset's tree is operator %s's", o.Output, b.Operator, terms.Operator)
		case !strings.EqualFold(hex.EncodeToString(out.ScriptPubKey), b.ScriptPubKey):
			return nil, nil, refuse("tree output %d: its script is not the board its record builds", o.Output)
		case hex.EncodeToString(out.Asset) != hex.EncodeToString(explicitAssetCommit(asset.ID)):
			return nil, nil, refuse("tree output %d: it does not hold asset %s explicitly", o.Output, asset.ID)
		case !explicit || atoms != value:
			return nil, nil, refuse("tree output %d: it holds %d atoms, and its record's board holds %s", o.Output, atoms, b.Value)
		}
		var holder *store.User
		var exists *store.TreeLeaf
		s.st.View(func(st *store.State) {
			holder = userByKey(st, b.Holder)
			if l, ok := st.TreeLeaves[strings.ToLower(b.Salt)]; ok {
				cp := *l
				exists = &cp
			}
		})
		if holder == nil {
			return nil, nil, refuse("tree output %d: its leaf is held by key %s, which no account here registered: a restricted asset reaches registered holders only", o.Output, b.Holder)
		}
		if exists != nil && !(exists.BoardTxid == txid && exists.BoardVout == uint32(o.Output)) {
			return nil, nil, refuse("tree output %d: a leaf at salt %s is in the register already", o.Output, b.Salt)
		}
		admitted[strings.ToLower(b.ScriptPubKey)] = holder
		leaves = append(leaves, &store.TreeLeaf{
			Salt: strings.ToLower(b.Salt), Asset: asset.ID, HolderAID: holder.AID, Holder: strings.ToLower(b.Holder),
			Atoms: value, State: store.LeafBoarding, BoardTxid: txid, BoardVout: uint32(o.Output),
			ExitScript: strings.ToLower(b.LeafScriptPubKey),
			Scripts: []store.LeafScript{
				{ScriptPubKey: strings.ToLower(b.ScriptPubKey), ClawControl: optHex(b.ClawControl)},
				{ScriptPubKey: strings.ToLower(b.LeafScriptPubKey), ClawControl: optHex(b.LeafClawControl)},
			},
			Height: -1, Created: time.Now().UTC(),
		})
	}
	return admitted, leaves, nil
}

var errNoTreeTool = errors.New(noTreeTool)

// registerBoards writes the leaves a co-signed board transaction made. A leaf
// at the same salt from the same output (the same co-sign asked again) stays
// as it is.
func (s *Server) registerBoards(leaves []*store.TreeLeaf) error {
	if len(leaves) == 0 {
		return nil
	}
	err := s.st.Update(func(st *store.State) error {
		for _, l := range leaves {
			if _, ok := st.TreeLeaves[l.Salt]; ok {
				continue
			}
			cp := *l
			st.TreeLeaves[l.Salt] = &cp
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, l := range leaves {
		s.st.AppendLog("tree_board", map[string]any{"asset": l.Asset, "salt": l.Salt, "holder": l.HolderAID,
			"atoms": l.Atoms, "board": fmt.Sprintf("%s:%d", l.BoardTxid, l.BoardVout)})
	}
	return nil
}

// --- reassignment ------------------------------------------------------------

type toolTransfer struct {
	Asset  string `json:"asset"`
	Inputs []struct {
		Salt               string `json:"salt"`
		Holder             string `json:"holder"`
		Value              string `json:"value"`
		CheckpointValue    string `json:"checkpoint_value"`
		CheckpointDigest   string `json:"checkpoint_digest"`
		ReassignmentDigest string `json:"reassignment_digest"`
	} `json:"inputs"`
	Outputs []struct {
		Salt         string  `json:"salt"`
		Holder       string  `json:"holder"`
		Value        string  `json:"value"`
		ScriptPubKey string  `json:"script_pubkey"`
		ClawControl  *string `json:"claw_control"`
	} `json:"outputs"`
}

func digest32(h string) ([32]byte, error) {
	var d [32]byte
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 32 {
		return d, fmt.Errorf("arca-enclave transfer answered a digest that is not 32 bytes of hex: %q", h)
	}
	copy(d[:], b)
	return d, nil
}

// treeTransferAnswer is what an approved reassignment is answered with.
func treeTransferAnswer(t *store.TreeTransfer, policy string) map[string]any {
	return map[string]any{"id": t.ID, "policy": policy, "signatures": t.Signatures}
}

func (s *Server) handleTreeTransfer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Asset    string          `json:"asset"`
		Transfer json.RawMessage `json:"transfer"`
	}
	if err := decodeBody(r, &req); err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	if s.treeTool == nil {
		httpErr(w, 501, noTreeTool)
		return
	}
	var asset *store.Asset
	s.st.View(func(st *store.State) {
		if a, ok := st.Assets[req.Asset]; ok {
			cp := *a
			asset = &cp
		}
	})
	if asset == nil {
		httpErr(w, 404, "unknown asset %s", req.Asset)
		return
	}
	if asset.Tree == nil {
		httpErr(w, 403, "asset %s has no tree: the issuer has not enabled one (POST /v1/issuer/tree)", asset.ID)
		return
	}
	// The terms come from this server's record of the asset, never from the
	// caller: the tool builds every script and message with them.
	var body map[string]any
	if err := json.Unmarshal(req.Transfer, &body); err != nil || body == nil {
		httpErr(w, 400, "transfer must be the tool's transfer request, an object")
		return
	}
	body["genesis"] = s.genesisDisplay()
	body["operator"] = asset.Tree.Operator
	body["policy"] = asset.Tree.Policy
	body["clawback"] = asset.Tree.Clawback
	in, _ := json.Marshal(body)

	mu := s.treeLock(asset.ID)
	mu.Lock()
	defer mu.Unlock()

	raw, err := s.treeTool.Run("transfer", in)
	if err != nil {
		treeErr(w, err)
		return
	}
	var t toolTransfer
	if err := json.Unmarshal(raw, &t); err != nil {
		httpErr(w, 502, "arca-enclave transfer answered no transfer: %v", err)
		return
	}
	if !strings.EqualFold(t.Asset, asset.ID) || len(t.Inputs) == 0 || len(t.Outputs) == 0 {
		httpErr(w, 400, "the transfer moves asset %q with %d inputs and %d outputs: a tree transfer of %s spends at least one leaf into at least one",
			t.Asset, len(t.Inputs), len(t.Outputs), asset.ID)
		return
	}
	var digests [][32]byte
	idh := sha256.New()
	idh.Write([]byte("openamp-tree-transfer-v1"))
	idh.Write([]byte(strings.ToLower(asset.ID)))
	for _, i := range t.Inputs {
		for _, h := range []string{i.CheckpointDigest, i.ReassignmentDigest} {
			d, err := digest32(h)
			if err != nil {
				httpErr(w, 502, "%v", err)
				return
			}
			digests = append(digests, d)
			idh.Write(d[:])
		}
	}
	id := hex.EncodeToString(idh.Sum(nil))

	// The same request again: the answer it had.
	var prior *store.TreeTransfer
	s.st.View(func(st *store.State) {
		if p, ok := st.TreeTransfers[id]; ok {
			cp := *p
			prior = &cp
		}
	})
	if prior != nil {
		httpJSON(w, treeTransferAnswer(prior, asset.Tree.Policy))
		return
	}

	sender, recipients, sent, outLeaves, err := s.checkTreeTransfer(asset, &t)
	if err != nil {
		if pr, ok := err.(*PolicyRefusal); ok {
			logRefusal("tree_transfer", s.st, map[string]any{"asset": asset.ID, "reason": pr.Reason})
		}
		treeErr(w, err)
		return
	}
	var height int64
	s.st.View(func(st *store.State) { height = st.Height })
	if err := s.checkRules(asset, sender, recipients, 0, height); err != nil {
		if pr, ok := err.(*PolicyRefusal); ok {
			logRefusal("tree_transfer", s.st, map[string]any{"asset": asset.ID, "sender": sender.AID, "reason": pr.Reason})
		}
		treeErr(w, err)
		return
	}

	sigs := make([]store.TreeSignature, 0, len(digests))
	for n, d := range digests {
		sig, err := s.signer.SignPolicy(asset.ID, treeCosignMessage(d), PolicyContext{
			Action: "tree-transfer", AID: sender.AID, TxID: id, InputIndex: n / 2,
		})
		if err != nil {
			httpErr(w, 500, "%v", err)
			return
		}
		sigs = append(sigs, store.TreeSignature{Digest: hex.EncodeToString(d[:]), Signature: hex.EncodeToString(sig)})
	}
	rec := &store.TreeTransfer{ID: id, Asset: asset.ID, SenderAID: sender.AID, Atoms: sent, Signatures: sigs,
		Height: height, Created: time.Now().UTC()}
	for _, i := range t.Inputs {
		rec.Inputs = append(rec.Inputs, strings.ToLower(i.Salt))
	}
	for _, l := range outLeaves {
		rec.Outputs = append(rec.Outputs, l.Salt)
	}
	err = s.st.Update(func(st *store.State) error {
		for _, salt := range rec.Inputs {
			l := st.TreeLeaves[salt]
			if l == nil || l.State != store.LeafLive {
				return refuse("leaf %s is no longer live", salt)
			}
		}
		for _, salt := range rec.Inputs {
			st.TreeLeaves[salt].State = store.LeafSpent
			st.TreeLeaves[salt].SpentBy = id
		}
		for _, l := range outLeaves {
			l.MadeBy = id
			st.TreeLeaves[l.Salt] = l
		}
		st.TreeTransfers[id] = rec
		st.Transfers = append(st.Transfers, store.TransferRecord{
			Asset: asset.ID, SenderAID: sender.AID, Atoms: sent, Height: height, Kind: "tree", ID: id,
		})
		return nil
	})
	if err != nil {
		treeErr(w, err)
		return
	}
	s.st.AppendLog("tree_transfer", map[string]any{"id": id, "asset": asset.ID, "sender": sender.AID, "atoms": sent,
		"inputs": rec.Inputs, "outputs": rec.Outputs})
	httpJSON(w, treeTransferAnswer(rec, asset.Tree.Policy))
}

// checkTreeTransfer checks a tool-read reassignment against the register:
// every input a live leaf of one sender at the value the tool read, whose
// checkpoint keeps the whole coin; every output an enclave-1 leaf of a
// registered holder at a salt the register has never seen; every atom
// committed. It answers the sender, what each other holder receives, the total
// of that, and the leaves the transfer makes.
func (s *Server) checkTreeTransfer(asset *store.Asset, t *toolTransfer) (*store.User, map[string]uint64, uint64, []*store.TreeLeaf, error) {
	type inLeaf struct {
		leaf  *store.TreeLeaf
		value uint64
	}
	var ins []inLeaf
	var sender *store.User
	var in, out uint64
	var refusal error
	promote := map[string]string{} // salt -> board txid of a boarding input, to look up
	s.st.View(func(st *store.State) {
		seen := map[string]bool{}
		for n, i := range t.Inputs {
			salt := strings.ToLower(i.Salt)
			if seen[salt] {
				refusal = refuse("input %d spends leaf %s, which another input spends too", n, salt)
				return
			}
			seen[salt] = true
			l, ok := st.TreeLeaves[salt]
			if !ok {
				refusal = refuse("input %d spends leaf %s, which the register does not hold: this server knows only leaves it co-signed into the tree", n, salt)
				return
			}
			if l.Asset != asset.ID {
				refusal = refuse("input %d spends a leaf of asset %s", n, l.Asset)
				return
			}
			if l.State == store.LeafBoarding {
				promote[salt] = l.BoardTxid
			} else if l.State != store.LeafLive {
				refusal = refuse("input %d spends leaf %s, which is %s", n, salt, l.State)
				return
			}
			if !strings.EqualFold(l.Holder, i.Holder) {
				refusal = refuse("input %d spends leaf %s of key %s, and the request names key %s", n, salt, l.Holder, i.Holder)
				return
			}
			v, _ := strconv.ParseUint(i.Value, 10, 64)
			cv, _ := strconv.ParseUint(i.CheckpointValue, 10, 64)
			if v != l.Atoms {
				refusal = refuse("input %d spends leaf %s of %d atoms, and the request says %s", n, salt, l.Atoms, i.Value)
				return
			}
			if cv != v {
				refusal = refuse("input %d: its checkpoint keeps %s of the coin's %s atoms: a checkpoint of a restricted coin keeps the whole coin, since any remainder could go anywhere", n, i.CheckpointValue, i.Value)
				return
			}
			u := st.Users[l.HolderAID]
			if u == nil {
				refusal = refuse("input %d spends a leaf of account %s, which is not registered", n, l.HolderAID)
				return
			}
			if sender == nil {
				cp := *u
				sender = &cp
			} else if sender.AID != u.AID {
				refusal = refuse("the inputs are leaves of two holders, %s and %s: one tree transfer has one sender", sender.AID, u.AID)
				return
			}
			cp := *l
			ins = append(ins, inLeaf{leaf: &cp, value: v})
			in += v
		}
	})
	if refusal != nil {
		return nil, nil, 0, nil, refusal
	}
	// A board's leaf is live once its board transaction is in a block; ask the
	// chain for one the follower has not reached yet.
	for salt, txid := range promote {
		h, err := s.txHeight(txid)
		if err != nil {
			return nil, nil, 0, nil, err
		}
		if h < 0 {
			return nil, nil, 0, nil, refuse("leaf %s rests on board %s, which is in no block yet", salt, txid)
		}
		if err := s.st.Update(func(st *store.State) error {
			if l := st.TreeLeaves[salt]; l != nil && l.State == store.LeafBoarding {
				l.State, l.Height = store.LeafLive, h
			}
			return nil
		}); err != nil {
			return nil, nil, 0, nil, err
		}
	}
	if sender.Frozen {
		return nil, nil, 0, nil, refuse("sender frozen")
	}
	recipients := map[string]uint64{}
	var leaves []*store.TreeLeaf
	s.st.View(func(st *store.State) {
		seen := map[string]bool{}
		for n, o := range t.Outputs {
			salt := strings.ToLower(o.Salt)
			if _, ok := st.TreeLeaves[salt]; ok || seen[salt] {
				refusal = refuse("output %d is a leaf at salt %s, which the register holds already", n, salt)
				return
			}
			seen[salt] = true
			u := userByKey(st, o.Holder)
			if u == nil {
				refusal = refuse("output %d pays key %s, which no account here registered: a restricted asset reaches registered holders only", n, o.Holder)
				return
			}
			if u.Frozen && u.AID != asset.IssuerAID && u.AID != sender.AID {
				refusal = refuse("recipient %s frozen", u.AID)
				return
			}
			v, _ := strconv.ParseUint(o.Value, 10, 64)
			if v == 0 {
				refusal = refuse("output %d holds nothing", n)
				return
			}
			out += v
			if u.AID != sender.AID {
				recipients[u.AID] += v
			}
			leaves = append(leaves, &store.TreeLeaf{
				Salt: salt, Asset: asset.ID, HolderAID: u.AID, Holder: strings.ToLower(o.Holder), Atoms: v,
				State: store.LeafLive, ExitScript: strings.ToLower(o.ScriptPubKey),
				Scripts: []store.LeafScript{{ScriptPubKey: strings.ToLower(o.ScriptPubKey), ClawControl: optHex(o.ClawControl)}},
				Height:  -1, Created: time.Now().UTC(),
			})
		}
	})
	if refusal != nil {
		return nil, nil, 0, nil, refusal
	}
	if out != in {
		return nil, nil, 0, nil, refuse("the outputs take %d of the inputs' %d atoms: a tree transfer of a restricted asset commits every atom, since a remainder could go anywhere", out, in)
	}
	var sent uint64
	for _, v := range recipients {
		sent += v
	}
	return sender, recipients, sent, leaves, nil
}

func (s *Server) handleTreeTransferDrop(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var rec *store.TreeTransfer
	s.st.View(func(st *store.State) {
		if t, ok := st.TreeTransfers[id]; ok {
			cp := *t
			rec = &cp
		}
	})
	if rec == nil {
		httpErr(w, 404, "no tree transfer %s", id)
		return
	}
	mu := s.treeLock(rec.Asset)
	mu.Lock()
	defer mu.Unlock()
	code := 200
	err := s.st.Update(func(st *store.State) error {
		t, ok := st.TreeTransfers[id]
		if !ok {
			code = 404
			return fmt.Errorf("no tree transfer %s", id)
		}
		for _, salt := range t.Outputs {
			l := st.TreeLeaves[salt]
			if l == nil || l.State != store.LeafLive {
				code = 409
				state := "gone"
				if l != nil {
					state = l.State
				}
				return fmt.Errorf("output leaf %s of transfer %s is %s: the transfer was used, and is no longer dropped", salt, id, state)
			}
		}
		for _, salt := range t.Outputs {
			delete(st.TreeLeaves, salt)
		}
		for _, salt := range t.Inputs {
			if l := st.TreeLeaves[salt]; l != nil && l.SpentBy == id {
				l.State, l.SpentBy = store.LeafLive, ""
			}
		}
		kept := st.Transfers[:0]
		for _, tr := range st.Transfers {
			if !(tr.Kind == "tree" && tr.ID == id) {
				kept = append(kept, tr)
			}
		}
		st.Transfers = kept
		delete(st.TreeTransfers, id)
		return nil
	})
	if err != nil {
		if code == 200 {
			code = 500
		}
		httpErr(w, code, "%v", err)
		return
	}
	s.st.AppendLog("tree_transfer_drop", map[string]any{"id": id, "asset": rec.Asset})
	httpJSON(w, map[string]any{"id": id, "dropped": true, "inputs": rec.Inputs})
}

// --- the chain ---------------------------------------------------------------

// txOnChain is a transaction and the height of its block, -1 while it is in
// none: from the node, or from the explorer when the node keeps no index.
func (s *Server) txOnChain(txid string) (*elements.Tx, int64, error) {
	var v struct {
		Hex           string `json:"hex"`
		Confirmations int64  `json:"confirmations"`
	}
	if err := s.node.Call(&v, "getrawtransaction", txid, true); err == nil && v.Hex != "" {
		tx, err := elements.DeserializeTx(mustHexBytes(v.Hex))
		if err != nil {
			return nil, -1, err
		}
		if v.Confirmations <= 0 {
			return tx, -1, nil
		}
		tip, err := s.node.GetBlockCount()
		if err != nil {
			return nil, -1, err
		}
		return tx, tip - v.Confirmations + 1, nil
	}
	raw, err := s.rawTxViaElectrs(txid)
	if err != nil {
		return nil, -1, fmt.Errorf("transaction %s: %v", txid, err)
	}
	tx, err := elements.DeserializeTx(mustHexBytes(raw))
	if err != nil {
		return nil, -1, err
	}
	resp, err := http.Get(strings.TrimRight(s.cfg.ElectrsURL, "/") + "/tx/" + txid + "/status")
	if err != nil {
		return nil, -1, err
	}
	defer resp.Body.Close()
	var st struct {
		Confirmed   bool  `json:"confirmed"`
		BlockHeight int64 `json:"block_height"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil || !st.Confirmed {
		return tx, -1, nil
	}
	return tx, st.BlockHeight, nil
}

func (s *Server) txHeight(txid string) (int64, error) {
	_, h, err := s.txOnChain(txid)
	return h, err
}

// handleTreeExited closes a live leaf whose holder took it home: a transaction
// in a block that spends the leaf's own script and pays the holder's enclave
// the leaf's atoms, explicitly, at output 0. Anyone may report it; the chain
// is the proof.
func (s *Server) handleTreeExited(w http.ResponseWriter, r *http.Request) {
	salt := strings.ToLower(r.PathValue("salt"))
	var req struct {
		Txid string `json:"txid"`
	}
	if err := decodeBody(r, &req); err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	var leaf *store.TreeLeaf
	var holder *store.User
	var asset *store.Asset
	s.st.View(func(st *store.State) {
		if l, ok := st.TreeLeaves[salt]; ok {
			cp := *l
			leaf = &cp
			if u, ok := st.Users[l.HolderAID]; ok {
				cu := *u
				holder = &cu
			}
			if a, ok := st.Assets[l.Asset]; ok {
				ca := *a
				asset = &ca
			}
		}
	})
	if leaf == nil {
		httpErr(w, 404, "no leaf at salt %s", salt)
		return
	}
	if leaf.State != store.LeafLive {
		httpErr(w, 409, "leaf %s is %s, not live", salt, leaf.State)
		return
	}
	if holder == nil || asset == nil {
		httpErr(w, 500, "leaf %s names an account or an asset the register lost", salt)
		return
	}
	tx, height, err := s.txOnChain(req.Txid)
	if err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	if height < 0 {
		httpErr(w, 409, "transaction %s is in no block yet: report the exit once it is", req.Txid)
		return
	}
	spent, err := s.spentOutputs(tx)
	if err != nil {
		treeErr(w, err)
		return
	}
	spendsLeaf := false
	for _, so := range spent {
		if strings.EqualFold(hex.EncodeToString(so.ScriptPubKey), leaf.ExitScript) {
			spendsLeaf = true
		}
	}
	enclave, err := s.treeFor(holder, asset)
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	var paid uint64
	pays := false
	if len(tx.Out) > 0 {
		o := tx.Out[0]
		paid, _ = elements.ExplicitValueAmount(o.Value)
		pays = bytes.Equal(o.ScriptPubKey, enclave.ScriptPubKey()) &&
			bytes.Equal(o.Asset, explicitAssetCommit(asset.ID)) && paid == leaf.Atoms
	}
	if !spendsLeaf || !pays {
		httpErr(w, 403, "transaction %s is no exit of leaf %s: an exit spends the leaf's script and pays its holder's enclave %d atoms at output 0", req.Txid, salt, leaf.Atoms)
		return
	}
	if err := s.st.Update(func(st *store.State) error {
		l := st.TreeLeaves[salt]
		if l == nil || l.State != store.LeafLive {
			return fmt.Errorf("leaf %s changed meanwhile", salt)
		}
		l.State, l.Closed, l.ClosedHeight = store.LeafExited, req.Txid, height
		return nil
	}); err != nil {
		httpErr(w, 409, "%v", err)
		return
	}
	s.st.AppendLog("tree_exit", map[string]any{"asset": asset.ID, "salt": salt, "holder": holder.AID,
		"atoms": leaf.Atoms, "txid": req.Txid})
	httpJSON(w, map[string]any{"salt": salt, "state": store.LeafExited, "txid": req.Txid, "height": height})
}

// --- clawback ----------------------------------------------------------------

// handleTreeClawback signs the policy half of a claw leaf's spend of one live
// leaf, where the asset elected clawback: the issuer's power over a coin in
// the tree is the power it holds over the enclave the coin exits to. The
// spend must take the leaf at one of the outputs it can be on the chain at,
// by its claw leaf, and pay the asset only to the issuer's enclave or a burn.
// Only the leaf that holds the coin now is clawed back: a leaf the holder
// reassigned is no longer the holder's, and its coin belongs to the leaves
// the transfer made.
func (s *Server) handleTreeClawback(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Asset  string `json:"asset"`
		Salt   string `json:"salt"`
		Tx     string `json:"tx"`
		Input  int    `json:"input"`
		Reason string `json:"reason"`
	}
	if err := decodeBody(r, &req); err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	if req.Reason == "" {
		httpErr(w, 400, "a reason is required; it becomes part of the public transparency log")
		return
	}
	if s.treeTool == nil {
		httpErr(w, 501, noTreeTool)
		return
	}
	salt := strings.ToLower(req.Salt)
	var asset *store.Asset
	var leaf *store.TreeLeaf
	var issuer *store.User
	s.st.View(func(st *store.State) {
		if a, ok := st.Assets[req.Asset]; ok {
			cp := *a
			asset = &cp
			if u, ok := st.Users[a.IssuerAID]; ok {
				cu := *u
				issuer = &cu
			}
		}
		if l, ok := st.TreeLeaves[salt]; ok {
			cp := *l
			leaf = &cp
		}
	})
	if asset == nil {
		httpErr(w, 404, "unknown asset %s", req.Asset)
		return
	}
	if !asset.Clawback || asset.Tree == nil || asset.Tree.Clawback == nil {
		httpErr(w, 403, "this asset was issued without a clawback leaf; its terms cannot be retrofitted")
		return
	}
	if leaf == nil || leaf.Asset != asset.ID {
		httpErr(w, 404, "no leaf of asset %s at salt %s", asset.ID, salt)
		return
	}
	if leaf.State != store.LeafLive {
		httpErr(w, 409, "leaf %s is %s: only a live leaf, the one that holds the coin now, is clawed back", salt, leaf.State)
		return
	}
	if issuer == nil {
		httpErr(w, 500, "the asset's issuer account %s is not registered", asset.IssuerAID)
		return
	}
	tx, err := elements.DeserializeTx(mustHexBytes(req.Tx))
	if err != nil {
		httpErr(w, 400, "tx: %v", err)
		return
	}
	if req.Input < 0 || req.Input >= len(tx.In) {
		httpErr(w, 400, "input %d out of range", req.Input)
		return
	}
	for i, out := range tx.Out {
		if len(out.Asset) != 33 || out.Asset[0] != 1 || len(out.Value) != 9 || out.Value[0] != 1 {
			httpErr(w, 400, "output %d is blinded: a clawback of a tree leaf is transparent, so the policy server can read where the asset goes", i)
			return
		}
	}
	tx.NormalizeWitness()
	spent, err := s.spentOutputs(tx)
	if err != nil {
		treeErr(w, err)
		return
	}
	spk := strings.ToLower(hex.EncodeToString(spent[req.Input].ScriptPubKey))
	control := ""
	for _, ls := range leaf.Scripts {
		if ls.ScriptPubKey == spk {
			control = ls.ClawControl
		}
	}
	if control == "" {
		httpErr(w, 403, "input %d spends no output leaf %s can be on the chain at by a claw leaf", req.Input, salt)
		return
	}
	issuerTree, err := s.treeFor(issuer, asset)
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	commit := explicitAssetCommit(asset.ID)
	var moved uint64
	for i, out := range tx.Out {
		if !bytes.Equal(out.Asset, commit) {
			continue
		}
		v, _ := elements.ExplicitValueAmount(out.Value)
		switch {
		case len(out.ScriptPubKey) == 0:
			httpErr(w, 403, "restricted asset in a fee output")
			return
		case len(out.ScriptPubKey) == 1 && out.ScriptPubKey[0] == 0x6a:
			if !asset.BurnAllowed {
				httpErr(w, 403, "burns are not permitted for this asset")
				return
			}
		case !bytes.Equal(out.ScriptPubKey, issuerTree.ScriptPubKey()):
			httpErr(w, 403, "output %d pays the asset elsewhere than the issuer's enclave: a clawback takes the coin to the issuer", i)
			return
		}
		moved += v
	}
	if moved == 0 {
		httpErr(w, 403, "the clawback pays nothing of the asset to the issuer")
		return
	}
	ix := elements.MustHex32(*asset.Tree.Clawback)
	px := elements.MustHex32(asset.Tree.Policy)
	clawLeaf := elements.CheckSigPair(ix, px)
	sh, err := elements.TaprootSighash(tx, spent, elements.SighashDefault, s.genesis, req.Input, clawLeaf)
	if err != nil {
		httpErr(w, 500, "sighash: %v", err)
		return
	}
	txid := tx.TxID()
	// Public notice precedes the signature.
	s.st.AppendLog("tree_clawback", map[string]any{"asset": asset.ID, "salt": salt, "holder": leaf.HolderAID,
		"atoms": leaf.Atoms, "reason": req.Reason, "txid": txid})
	policySig, err := s.signer.SignPolicy(asset.ID, sh, PolicyContext{
		Action: "clawback", AID: leaf.HolderAID, TxID: txid, Reason: req.Reason, InputIndex: req.Input,
	})
	if err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	resp := map[string]any{
		"input": req.Input, "sighash": hex.EncodeToString(sh[:]), "policy_sig": hex.EncodeToString(policySig),
		"leaf": hex.EncodeToString(clawLeaf), "control": control, "txid": txid,
	}
	// With the issuer key on this server (the testnet demo), sign its half too;
	// otherwise the issuer signs the same signature hash itself. The witness is
	// <policy_sig> <issuer_sig> <leaf> <control>.
	if !asset.IssuerExternal {
		if keys, err := s.st.LoadKeys(); err == nil {
			if ipriv, ok := keys["issuer:"+asset.ID]; ok {
				isig, err := elements.SignSchnorr(mustHexBytes(ipriv), sh)
				if err != nil {
					httpErr(w, 500, "%v", err)
					return
				}
				resp["issuer_sig"] = hex.EncodeToString(isig)
				resp["witness"] = []string{hex.EncodeToString(policySig), hex.EncodeToString(isig), hex.EncodeToString(clawLeaf), control}
			}
		}
	}
	if _, ok := resp["issuer_sig"]; !ok {
		resp["to_sign"] = map[string]any{"sighash": hex.EncodeToString(sh[:]), "pubkey": *asset.Tree.Clawback}
	}
	if err := s.st.Update(func(st *store.State) error {
		if l := st.TreeLeaves[salt]; l != nil && l.State == store.LeafLive {
			l.State, l.Closed = store.LeafClawed, txid
		}
		return nil
	}); err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	httpJSON(w, resp)
}

// followTree moves the register with the chain: a board leaf is live once its
// board transaction is in a block and boarding again when a reorganisation
// takes that block away; an exit taken away by one reopens its leaf.
func followTree(st *store.State, forkAt int64, confirmed map[string]int64) {
	for _, l := range st.TreeLeaves {
		if l.BoardTxid != "" {
			if forkAt >= 0 && l.Height >= forkAt && l.State == store.LeafLive {
				l.State, l.Height = store.LeafBoarding, -1
			}
			if h, ok := confirmed[l.BoardTxid]; ok && l.State == store.LeafBoarding {
				l.State, l.Height = store.LeafLive, h
			}
		}
		if l.State == store.LeafExited && forkAt >= 0 && l.ClosedHeight >= forkAt {
			if h, ok := confirmed[l.Closed]; ok {
				l.ClosedHeight = h
			} else {
				l.State, l.Closed, l.ClosedHeight = store.LeafLive, "", 0
			}
		}
	}
}
