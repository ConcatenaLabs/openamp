package damp

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/ConcatenaLabs/openamp/openampd/internal/damp/dmt"
)

// Covenant-facing policy construction, mirroring opendamp's src/policy.rs so the
// commitment this server publishes is the one the on-chain covenant verifies.
// The M2 half of this package speaks the snapshot document format; this half
// speaks the covenant's own dmt-v1 whitelist tree and the pi it is instantiated
// with. Both must stay pinned to opendamp's vectors/addresses.json.

// PolicyVersion is the version byte inside pi.
const PolicyVersion = 0x01

// ProgramRegistry pins program_id -> CMR. A CMR change is a different covenant
// and therefore a different address, so these are loaded from a file the
// operator controls rather than guessed, and the loader refuses partial sets.
type ProgramRegistry struct {
	UserCMR [32]byte
	// One primary program per transaction SHAPE, in menu order with the
	// canonical shape first. They all commit to the same policy and all live in
	// the one C_V(pi) address; see elements.VerifierCovenant.
	VerifierCMRs [][32]byte
	IssuerCMR    [32]byte
}

// VerifierCMR is the canonical shape's CMR, which is the one a wallet uses for
// an ordinary transfer.
func (r *ProgramRegistry) VerifierCMR() [32]byte { return r.VerifierCMRs[0] }

// LoadProgramRegistry reads the CMR pinning file produced by `opendamp
// registry` (or the vectors file, which carries the same fields under
// "programs"). Both shapes are accepted so an operator can point at either.
func LoadProgramRegistry(path string) (*ProgramRegistry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("program registry: %w", err)
	}
	type shapeDoc struct {
		Shape string `json:"shape"`
		CMR   string `json:"cmr"`
	}
	var doc struct {
		Programs struct {
			UCMR   string     `json:"u_cmr"`
			PCMR   string     `json:"p_cmr_canonical"`
			GCMR   string     `json:"g_cmr"`
			Shapes []shapeDoc `json:"verifier_shapes"`
		} `json:"programs"`
		UCMR   string     `json:"u_cmr"`
		PCMR   string     `json:"p_cmr_canonical"`
		GCMR   string     `json:"g_cmr"`
		Shapes []shapeDoc `json:"verifier_shapes"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("program registry: %w", err)
	}
	u, g, shapes := doc.Programs.UCMR, doc.Programs.GCMR, doc.Programs.Shapes
	if u == "" && g == "" && len(shapes) == 0 {
		u, g, shapes = doc.UCMR, doc.GCMR, doc.Shapes
	}
	if u == "" || g == "" || len(shapes) == 0 {
		return nil, fmt.Errorf(
			"program registry %s: needs u_cmr, g_cmr and a non-empty verifier_shapes menu. "+
				"A file carrying a single p_cmr predates the shape menu: regenerate it with "+
				"`opendamp vectors`, because a one-leaf taptree is a different address",
			path)
	}
	reg := &ProgramRegistry{}
	dec := func(field, h string, dst *[32]byte) error {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != 32 {
			return fmt.Errorf("program registry: %s %q is not a 32-byte CMR", field, h)
		}
		copy(dst[:], b)
		return nil
	}
	if err := dec("u_cmr", u, &reg.UserCMR); err != nil {
		return nil, err
	}
	if err := dec("g_cmr", g, &reg.IssuerCMR); err != nil {
		return nil, err
	}
	for _, sh := range shapes {
		var c [32]byte
		if err := dec("verifier_shapes["+sh.Shape+"]", sh.CMR, &c); err != nil {
			return nil, err
		}
		reg.VerifierCMRs = append(reg.VerifierCMRs, c)
	}
	return reg, nil
}

// WhitelistEntry is one approved holder and the height bounds that bind it.
// SendAfter is the lockup (the holder cannot own a regulated INPUT below that
// height, which is what makes removing a key a freeze), RecvAfter the receive
// window (cannot be paid below it, the Reg S pattern). Zero means unbounded.
// The bounds live IN the leaf, so the same proof that shows a key is approved
// shows which windows bind it, and shortening your own lockup changes the leaf
// so the path stops reaching the root.
type WhitelistEntry struct {
	Key       [32]byte
	SendAfter uint32
	RecvAfter uint32
}

// WhitelistRoot is the dmt-v1 root over the approved holders. The covenant
// checks both the owners of regulated inputs and the recipients of regulated
// outputs, so removing a key stops that holder spending as well as receiving.
func WhitelistRootWithWindows(entries []WhitelistEntry) ([32]byte, error) {
	es := make([]dmt.Entry, 0, len(entries))
	for _, e := range entries {
		es = append(es, dmt.Entry{Key: dmt.Key(e.Key), SendAfter: e.SendAfter, RecvAfter: e.RecvAfter})
	}
	tree, err := dmt.New(es)
	if err != nil {
		return [32]byte{}, err
	}
	return tree.Root(), nil
}

// WhitelistRoot is WhitelistRootWithWindows for the common case of holders with
// no height bounds, which is every holder until an issuer sets a lockup or a
// receive window.
func WhitelistRoot(keys [][32]byte) ([32]byte, error) {
	es := make([]WhitelistEntry, 0, len(keys))
	for _, k := range keys {
		es = append(es, WhitelistEntry{Key: k})
	}
	return WhitelistRootWithWindows(es)
}

// BlacklistRoot is the dmt-v1 INTERVAL root over the outpoint keys a policy
// refuses to let spend. Non-membership is proved by one membership proof of the
// interval bracketing the key plus two strict comparisons, which is what makes
// it affordable inside the covenant; the tree shape therefore differs from the
// whitelist's. An empty blacklist still has a root (the guard interval), so a
// policy that lists nothing commits to that root, never to zero.
func BlacklistRoot(outpointKeys [][32]byte) ([32]byte, error) {
	keys := make([]dmt.Key, 0, len(outpointKeys))
	for _, k := range outpointKeys {
		keys = append(keys, dmt.Key(k))
	}
	tree, err := dmt.NewIntervalTree(keys)
	if err != nil {
		return [32]byte{}, err
	}
	return tree.Root(), nil
}

// RulesRootCovenant is the fixed-order two-level Merkle root over the four
// predicate commitments [blacklist, whitelist, limit, contracts]; an absent
// predicate commits to 32 zero bytes. This is opendamp's src/policy.rs
// rules_root, NOT the M2 snapshot RulesRoot (which serves the document format);
// they are separate constructions on purpose and both are vector-pinned.
//
// contracts is ContractsCommitment of the policy's contract template list, or
// nil for a policy that lists none. Nothing else commits in that slot (dmt-v1
// refuses a class-keyed windows array), so a policy without contracts keeps
// the pi it would have had if contracts did not exist.
func RulesRootCovenant(blacklist, whitelist *[32]byte, limit uint64, contracts *[32]byte) [32]byte {
	var zero [32]byte
	pick := func(p *[32]byte) [32]byte {
		if p == nil {
			return zero
		}
		return *p
	}
	cBl, cWl, cWin := pick(blacklist), pick(whitelist), pick(contracts)
	var cLim [32]byte
	if limit != 0 {
		binary.BigEndian.PutUint64(cLim[24:], limit)
	}
	left := sha256.Sum256(append(append([]byte{}, cBl[:]...), cWl[:]...))
	right := sha256.Sum256(append(append([]byte{}, cLim[:]...), cWin[:]...))
	return sha256.Sum256(append(append([]byte{}, left[:]...), right[:]...))
}

// PiCovenant is the policy commitment the verifier covenant is instantiated
// with: H_"OpenDAMP/policy/v1"(version || asset_internal || seq_be64 ||
// rules_root). assetInternal is the asset id in internal (hash) byte order,
// which is the display id reversed.
func PiCovenant(assetInternal [32]byte, seq uint64, rulesRoot [32]byte) [32]byte {
	msg := make([]byte, 0, 1+32+8+32)
	msg = append(msg, PolicyVersion)
	msg = append(msg, assetInternal[:]...)
	var seqBE [8]byte
	binary.BigEndian.PutUint64(seqBE[:], seq)
	msg = append(msg, seqBE[:]...)
	msg = append(msg, rulesRoot[:]...)
	return taggedHash("OpenDAMP/policy/v1", msg)
}

// ContractTemplate is a contract template a policy can list, so that the asset
// can enter its instances (opendamp's DESIGN.md section 2.4). The verifier
// recognises an instance by rebuilding its script from the template's
// commitment root; this server only lists and commits.
type ContractTemplate struct {
	// Name is the descriptor's template name.
	Name string
	// TemplateHash is the descriptor's template hash, which is how a policy
	// lists the template.
	TemplateHash [32]byte
	// CMR is the template's one program root, in the descriptor's byte order.
	CMR [32]byte
}

// TagContracts is the domain of the contract-list commitment.
const TagContracts = "OpenDAMP/contracts/v1"

// Whitelistable is every template a policy can list, mirroring opendamp's
// contracts::WHITELISTABLE. A template joins only with a guard (every path
// needs q of the asset's verifier asset at input 0) and an owner term, so that
// the verifier is in every transaction that moves the contract's coin; a
// listing naming anything else is refused, because the verifier would not let
// the asset into it.
var Whitelistable = []ContractTemplate{
	{
		Name:         "seqdex/guarded-order",
		TemplateHash: mustHex32("d68cecbf19c501abc78987833bec226e4a081ef19e484c0b060d3033b4239f60"),
		CMR:          mustHex32("c676964fbb78174782e24f18b5fb3fdd65a844d7317ca43b84547807461ca659"),
	},
}

func mustHex32(s string) [32]byte {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		panic("damp: bad 32-byte constant " + s)
	}
	return [32]byte(b)
}

// LookupContractTemplate finds a whitelistable template by its name or its
// template hash in hex.
func LookupContractTemplate(nameOrHash string) (ContractTemplate, bool) {
	k := strings.ToLower(strings.TrimSpace(nameOrHash))
	for _, t := range Whitelistable {
		if k == t.Name || k == hex.EncodeToString(t.TemplateHash[:]) {
			return t, true
		}
	}
	return ContractTemplate{}, false
}

// ContractsCommitment commits a policy's contract template list:
// H_"OpenDAMP/contracts/v1"(hash_1 || ... || hash_n) over the template hashes
// in ascending order. It is the fourth slot of RulesRootCovenant; a policy that
// lists nothing passes nil there instead.
func ContractsCommitment(hashes [][32]byte) [32]byte {
	sorted := append([][32]byte(nil), hashes...)
	sort.Slice(sorted, func(i, j int) bool { return bytes.Compare(sorted[i][:], sorted[j][:]) < 0 })
	chunks := make([][]byte, 0, len(sorted))
	for i := range sorted {
		chunks = append(chunks, sorted[i][:])
	}
	return taggedHash(TagContracts, chunks...)
}

// ContractsRoot parses a snapshot's contract list, the hex template hashes in
// ascending order with no repeat, each a whitelistable template, and returns
// its commitment, or nil for an empty list.
func ContractsRoot(list []string) (*[32]byte, error) {
	if len(list) == 0 {
		return nil, nil
	}
	hashes := make([][32]byte, 0, len(list))
	for i, h := range list {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != 32 || h != strings.ToLower(h) {
			return nil, fmt.Errorf("predicates.contracts[%d] must be a 32-byte lower-case hex template hash", i)
		}
		if _, ok := LookupContractTemplate(h); !ok {
			return nil, fmt.Errorf("predicates.contracts[%d]: %s is not a template a policy can list (known: %s)", i, h, knownTemplates())
		}
		if i > 0 && list[i-1] >= h {
			return nil, fmt.Errorf("predicates.contracts must be in ascending order with no repeat, so that a list has one encoding")
		}
		hashes = append(hashes, [32]byte(b))
	}
	c := ContractsCommitment(hashes)
	return &c, nil
}

func knownTemplates() string {
	names := make([]string, 0, len(Whitelistable))
	for _, t := range Whitelistable {
		names = append(names, t.Name+" "+hex.EncodeToString(t.TemplateHash[:]))
	}
	return strings.Join(names, ", ")
}
