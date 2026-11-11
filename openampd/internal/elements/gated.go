package elements

import "fmt"

// The gated order: a holder's resting offer to sell a restricted asset on the
// chain, filled by anyone the asset's rules admit while its maker is offline.
//
// P2TR(NUMS, [fill, [refund, claw]]) or P2TR(NUMS, [fill, refund]):
//
//	fill  : <K_policy> OP_CHECKSIGVERIFY <a SeqDEX fill covenant>
//	refund: <expiry> OP_CHECKLOCKTIMEVERIFY OP_DROP <home: the maker's enclave, the whole coin>
//	claw  : <K_issuer> OP_CHECKSIGVERIFY <K_policy> OP_CHECKSIG
//
// The fill is SeqDEX's tapscript fill covenant (seqdex daemon/pkg/covenant,
// BuildFillLeaf) with the policy key's signature checked first, on a clean
// stack: the witness is [policy sig, leaf, control]. The covenant pays the
// maker at output 2k and keeps the remainder at the same script at 2k+1; the
// signature, over the whole transaction, is this server's decision on the
// fill, with the maker as sender and the taker as recipient. A fill nobody
// co-signed cannot happen, and the remainder stays gated.
//
// The refund needs no key: after the expiry (a time) the coin must be input 0,
// and output 0 must pay the coin's whole value, read from the input itself
// because a partial fill leaves less than was locked, in the asset to the
// maker's enclave:
//
//	OP_PUSHCURRENTINPUTINDEX OP_0 OP_EQUALVERIFY
//	OP_0 OP_INSPECTOUTPUTSCRIPTPUBKEY OP_1 OP_EQUALVERIFY <program> OP_EQUALVERIFY
//	OP_0 OP_INSPECTOUTPUTASSET OP_1 OP_EQUALVERIFY <asset> OP_EQUALVERIFY
//	OP_0 OP_INSPECTOUTPUTVALUE OP_1 OP_EQUALVERIFY
//	OP_0 OP_INSPECTINPUTVALUE OP_1 OP_EQUALVERIFY OP_EQUAL
//
// Input 0 and output 0 for the reason htlc.go gives: no keyless path may
// accept an output another covenant in the same transaction also counts. The
// fill pays relative to its own index (2k and 2k+1), so beside a refund at
// input 0 it pays outputs 2 and above.

const (
	opInspectInputValue = 0xc9

	// GatedFillMax bounds the wrapped fill covenant's size.
	GatedFillMax = 1000
)

// GatedOrderTerms are everything a gated order's scripts commit to.
type GatedOrderTerms struct {
	PolicyX      [32]byte  // the asset's policy key
	Fill         []byte    // the SeqDEX fill covenant the order wraps, without the gate
	IssuerX      *[32]byte // the clawback key, only where the asset elected clawback
	Expiry       uint32    // the refund opens at this median time past (>= MinTimeLock)
	MakerProgram [32]byte  // the maker's enclave: its v1 witness program
	Asset        [32]byte  // the restricted asset, internal byte order
}

// GatedFillLeaf is the policy gate followed by the fill covenant.
func GatedFillLeaf(policyX [32]byte, fill []byte) []byte {
	s := make([]byte, 0, 34+len(fill))
	s = append(s, 0x20)
	s = append(s, policyX[:]...)
	s = append(s, opCheckSigVerify)
	return append(s, fill...)
}

// GatedOrderTree builds the gated order: leaves "fill", "refund" and, with
// clawback, "claw".
func GatedOrderTree(t GatedOrderTerms) (*TapTree, error) {
	if t.Expiry < MinTimeLock {
		return nil, fmt.Errorf("expiry %d is a height: an order's expiry is a time (>= %d)", t.Expiry, MinTimeLock)
	}
	if len(t.Fill) == 0 || len(t.Fill) > GatedFillMax {
		return nil, fmt.Errorf("the fill covenant must be 1 to %d bytes", GatedFillMax)
	}
	refund := timeLock(t.Expiry)
	refund = append(refund, opPushCurrentInputIndex, op0, opEqualVerify)
	refund = append(refund, op0, opInspectOutputScriptPub, op1, opEqualVerify)
	refund = append(refund, pushData(t.MakerProgram[:])...)
	refund = append(refund, opEqualVerify, op0, opInspectOutputAsset, op1, opEqualVerify)
	refund = append(refund, pushData(t.Asset[:])...)
	refund = append(refund, opEqualVerify, op0, opInspectOutputValue, op1, opEqualVerify)
	refund = append(refund, op0, opInspectInputValue, op1, opEqualVerify, opEqual)
	leaves := []Leaf{
		{Name: "fill", Script: GatedFillLeaf(t.PolicyX, t.Fill)},
		{Name: "refund", Script: refund},
	}
	if t.IssuerX != nil {
		leaves = append(leaves, Leaf{Name: "claw", Script: CheckSigPair(*t.IssuerX, t.PolicyX)})
	}
	return BuildTree(NUMS, leaves...)
}
