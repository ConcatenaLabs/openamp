package elements

import (
	"encoding/binary"
	"fmt"
)

// The swap escrow and its fee pot: the Sequentia side of a restricted asset
// traded for on-chain BTC. The BTC payer (the buyer) holds a secret s with
// H = SHA256(s). The seller locks the asset in the escrow and a little of an
// accepted fee asset in the pot, in one transaction. The buyer claims both
// together with s, which the pot's witness reveals in plain tapscript. After
// T_seq, a time, anyone can send each back where it came from: there is no key
// on the way home, so no refusal and no absence can keep a coin from its
// owner, and the buyer cannot outwait the refund with a withheld claim.
//
// Escrow, P2TR(NUMS, [claim, [refund, claw]]) or P2TR(NUMS, [claim, refund]):
//
//	claim : OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <H> OP_EQUALVERIFY
//	        <K_buyer> OP_CHECKSIGVERIFY <K_policy> OP_CHECKSIG
//	refund: <T_seq> OP_CHECKLOCKTIMEVERIFY OP_DROP <home: the seller's enclave>
//	claw  : <K_issuer> OP_CHECKSIGVERIFY <K_policy> OP_CHECKSIG
//
// Fee pot, P2TR(NUMS, [claim, refund]):
//
//	claim : OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <H> OP_EQUALVERIFY <K_buyer> OP_CHECKSIG
//	refund: <T_seq> OP_CHECKLOCKTIMEVERIFY OP_DROP <home: the seller's address>
//
// A way home requires the coin to be spent as input 0 and output 0 to carry
// exactly the given program, the given explicit asset and the given explicit
// value:
//
//	OP_PUSHCURRENTINPUTINDEX OP_0 OP_EQUALVERIFY
//	OP_PUSHCURRENTINPUTINDEX OP_DUP OP_DUP
//	OP_INSPECTOUTPUTSCRIPTPUBKEY <version> OP_EQUALVERIFY <program> OP_EQUALVERIFY
//	OP_INSPECTOUTPUTASSET OP_1 OP_EQUALVERIFY <asset> OP_EQUALVERIFY
//	OP_INSPECTOUTPUTVALUE OP_1 OP_EQUALVERIFY <value, 8 bytes LE> OP_EQUAL
//
// Input 0 and output 0, and nothing else, because a keyless path must never
// accept an output that another covenant in the same transaction also counts
// as its own. A refund pinned to a fixed output 0 from any input would share
// that output with a second refund of equal value. A refund pinned to "the
// output at my own input index" would share output 2k with a SeqDEX order at
// input k, which pays its maker there: with both paying the seller, a taker
// could fill the seller's own resting order with the seller's own refund. With
// the refund at input 0, only one refund fits in a transaction, and every
// covenant of this project that pays relative to its own index (SeqDEX orders
// at 2k, the gated order, OpenDAMP's guarded order) pays outputs >= 2 from any
// input >= 1. So each refund is a transaction of its own, with fee inputs
// after it.

const (
	opSize                   = 0x82
	opEqual                  = 0x87
	opEqualVerify            = 0x88
	opSHA256                 = 0xa8
	opCheckSig               = 0xac
	opCheckSigVerify         = 0xad
	opCheckLockTimeVerify    = 0xb1
	opDrop                   = 0x75
	opDup                    = 0x76
	op0                      = 0x00
	op1                      = 0x51
	opPushCurrentInputIndex  = 0xcd
	opInspectOutputAsset     = 0xce
	opInspectOutputValue     = 0xcf
	opInspectOutputScriptPub = 0xd1

	// MinTimeLock is the smallest lock time read as a Unix time rather than a
	// block height. Every lock here is a time: Sequentia's height can stall
	// while Bitcoin's clock runs, and both legs of a swap must share one clock.
	MinTimeLock = 500_000_000
)

// SwapEscrowTerms are everything the escrow's scripts commit to.
type SwapEscrowTerms struct {
	Hash          [32]byte  // H = SHA256(s)
	BuyerX        [32]byte  // the buyer's enclave key
	PolicyX       [32]byte  // the asset's policy key
	IssuerX       *[32]byte // the clawback key, only where the asset elected clawback
	TSeq          uint32    // the refund opens at this median time past (>= MinTimeLock)
	SellerProgram [32]byte  // the seller's enclave: its v1 witness program
	Asset         [32]byte  // the restricted asset, internal byte order
	Value         uint64    // the escrowed atoms, all of which go home on a refund
}

// FeePotTerms are everything the fee pot's scripts commit to.
type FeePotTerms struct {
	Hash          [32]byte
	BuyerX        [32]byte
	TSeq          uint32
	SellerVersion byte   // the seller's payout address: witness version 0 or 1
	SellerProgram []byte // and program (20 or 32 bytes for v0, 32 for v1)
	FeeAsset      [32]byte
	Value         uint64
}

func (t *SwapEscrowTerms) check() error {
	if t.TSeq < MinTimeLock {
		return fmt.Errorf("T_seq %d is a height: every swap lock is a time (>= %d)", t.TSeq, MinTimeLock)
	}
	if t.Value == 0 {
		return fmt.Errorf("an escrow of zero atoms")
	}
	return nil
}

// SwapEscrowTree builds the escrow: leaves "claim", "refund" and, with
// clawback, "claw".
func SwapEscrowTree(t SwapEscrowTerms) (*TapTree, error) {
	if err := t.check(); err != nil {
		return nil, err
	}
	leaves := []Leaf{
		{Name: "claim", Script: append(hashLock(t.Hash), CheckSigPair(t.BuyerX, t.PolicyX)...)},
		{Name: "refund", Script: append(timeLock(t.TSeq), home(1, t.SellerProgram[:], t.Asset, t.Value)...)},
	}
	if t.IssuerX != nil {
		leaves = append(leaves, Leaf{Name: "claw", Script: CheckSigPair(*t.IssuerX, t.PolicyX)})
	}
	return BuildTree(NUMS, leaves...)
}

// FeePotTree builds the fee pot: leaves "claim" and "refund".
func FeePotTree(t FeePotTerms) (*TapTree, error) {
	if t.TSeq < MinTimeLock {
		return nil, fmt.Errorf("T_seq %d is a height: every swap lock is a time (>= %d)", t.TSeq, MinTimeLock)
	}
	switch {
	case t.SellerVersion == 0 && (len(t.SellerProgram) == 20 || len(t.SellerProgram) == 32):
	case t.SellerVersion == 1 && len(t.SellerProgram) == 32:
	default:
		return nil, fmt.Errorf("the pot's payout must be a v0 or v1 witness program")
	}
	if t.Value == 0 {
		return nil, fmt.Errorf("a fee pot of zero atoms")
	}
	claim := hashLock(t.Hash)
	claim = append(claim, 0x20)
	claim = append(claim, t.BuyerX[:]...)
	claim = append(claim, opCheckSig)
	return BuildTree(NUMS,
		Leaf{Name: "claim", Script: claim},
		Leaf{Name: "refund", Script: append(timeLock(t.TSeq), home(t.SellerVersion, t.SellerProgram, t.FeeAsset, t.Value)...)},
	)
}

func hashLock(h [32]byte) []byte {
	s := []byte{opSize, 0x01, 0x20, opEqualVerify, opSHA256, 0x20}
	s = append(s, h[:]...)
	return append(s, opEqualVerify)
}

func timeLock(t uint32) []byte {
	return append(pushNum(int64(t)), opCheckLockTimeVerify, opDrop)
}

// home: the coin is input 0, and output 0 pays exactly value of asset to the
// witness program of the given version.
func home(version byte, program []byte, asset [32]byte, value uint64) []byte {
	s := []byte{opPushCurrentInputIndex, op0, opEqualVerify}
	s = append(s, opPushCurrentInputIndex, opDup, opDup, opInspectOutputScriptPub)
	if version == 0 {
		s = append(s, op0)
	} else {
		s = append(s, op1+version-1)
	}
	s = append(s, opEqualVerify)
	s = append(s, pushData(program)...)
	s = append(s, opEqualVerify, opInspectOutputAsset, op1, opEqualVerify)
	s = append(s, pushData(asset[:])...)
	s = append(s, opEqualVerify, opInspectOutputValue, op1, opEqualVerify)
	var v [8]byte
	binary.LittleEndian.PutUint64(v[:], value)
	s = append(s, pushData(v[:])...)
	return append(s, opEqual)
}

// pushData is a minimal push of up to 75 bytes, which is all these scripts use.
func pushData(b []byte) []byte {
	if len(b) == 0 || len(b) > 75 {
		panic("pushData: 1 to 75 bytes")
	}
	return append([]byte{byte(len(b))}, b...)
}

// pushNum is the minimal CScriptNum push of a non-negative number.
func pushNum(n int64) []byte {
	if n == 0 {
		return []byte{op0}
	}
	if n >= 1 && n <= 16 {
		return []byte{op1 + byte(n) - 1}
	}
	var b []byte
	for v := n; v > 0; v >>= 8 {
		b = append(b, byte(v&0xff))
	}
	if b[len(b)-1]&0x80 != 0 {
		b = append(b, 0)
	}
	return pushData(b)
}
