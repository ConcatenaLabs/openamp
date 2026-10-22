package store

import "time"

// TreeTerms is what an asset's tree is held to: the operator key every
// enclave-1 leaf of the asset names, and the asset's own policy key and
// clawback key (empty when the asset elected no clawback). Policy and clawback
// are the asset's and never change; they are kept here so the published terms
// are one record.
type TreeTerms struct {
	Operator string  `json:"operator"` // x-only hex of the tree operator's key S
	Policy   string  `json:"policy"`   // x-only hex: the asset's policy key
	Clawback *string `json:"clawback"` // x-only hex: the issuer key of the claw leaf; null when none was elected
}

// Leaf states. A board leaf is boarding until the transaction that funds its
// board is in a block; every other leaf is live from the transfer that made
// it. Spent, exited and clawed leaves count toward no balance.
const (
	LeafBoarding = "boarding"
	LeafLive     = "live"
	LeafSpent    = "spent"
	LeafExited   = "exited"
	LeafClawed   = "clawed"
)

// LeafScript is one output a leaf can be on the chain at, with the control
// block of its claw leaf there (empty when the asset elected no clawback). A
// board leaf has two: the board output and the leaf its owner converts it
// into.
type LeafScript struct {
	ScriptPubKey string `json:"script_pubkey"`
	ClawControl  string `json:"claw_control,omitempty"`
}

// TreeLeaf is one enclave-1 leaf in the register, keyed by its salt: who holds
// it and how much, where it came from, and the outputs it can reach the chain
// at. It is written only by what this server co-signs: a board it admitted, a
// tree transfer it approved.
type TreeLeaf struct {
	Salt      string `json:"salt"`
	Asset     string `json:"asset"`
	HolderAID string `json:"holder_aid"`
	Holder    string `json:"holder"` // x-only hex of the holder's enclave key
	Atoms     uint64 `json:"atoms"`
	State     string `json:"state"`
	// Where the leaf came from: the board transaction and output, or the tree
	// transfer that made it.
	BoardTxid string `json:"board_txid,omitempty"`
	BoardVout uint32 `json:"board_vout,omitempty"`
	MadeBy    string `json:"made_by,omitempty"`
	// ExitScript is the leaf's own script: an exit spends it and pays the
	// holder's enclave.
	ExitScript string       `json:"exit_script"`
	Scripts    []LeafScript `json:"scripts"`
	// Height is the block of a board leaf's board transaction, -1 while it is
	// in none (and for a leaf a transfer made, which has no transaction).
	Height  int64  `json:"height"`
	SpentBy string `json:"spent_by,omitempty"` // the tree transfer that spent it
	// Closed is the txid of the exit or the clawback that took the leaf onto
	// the chain, ClosedHeight the exit's block.
	Closed       string    `json:"closed,omitempty"`
	ClosedHeight int64     `json:"closed_height,omitempty"`
	Created      time.Time `json:"created"`
}

// TreeSignature is one policy signature a tree transfer was answered with.
type TreeSignature struct {
	Digest    string `json:"digest"`
	Signature string `json:"signature"`
}

// TreeTransfer is an approved reassignment of leaves in an asset's tree. A
// repeated request gets the signatures stored here, never new ones.
type TreeTransfer struct {
	ID         string          `json:"id"`
	Asset      string          `json:"asset"`
	SenderAID  string          `json:"sender_aid"`
	Atoms      uint64          `json:"atoms"` // what left the sender: the outputs to other holders
	Inputs     []string        `json:"inputs"`
	Outputs    []string        `json:"outputs"`
	Signatures []TreeSignature `json:"signatures"`
	Height     int64           `json:"height"`
	Created    time.Time       `json:"created"`
}

// LiveTreeAtoms is what each holder holds in live leaves of asset.
func LiveTreeAtoms(st *State, asset string) map[string]uint64 {
	out := map[string]uint64{}
	for _, l := range st.TreeLeaves {
		if l.Asset == asset && l.State == LeafLive {
			out[l.HolderAID] += l.Atoms
		}
	}
	return out
}
