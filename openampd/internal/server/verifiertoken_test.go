package server

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ConcatenaLabs/openamp/openampd/internal/elements"
	"github.com/ConcatenaLabs/openamp/openampd/internal/fastmerkle"
	"github.com/ConcatenaLabs/openamp/openampd/internal/rpc"
	"github.com/ConcatenaLabs/openamp/openampd/internal/store"
)

// V's token against a node is opendamp's regtest proof and the owner-script
// rehearsal; these tests pin what this server does around the tool.

// dampVerifierFixture turns the oa4 fixture's asset into a network-enforced one
// whose verifier asset V was issued by a recorded transaction, and returns V's
// display id and token.
func dampVerifierFixture(t *testing.T, f *oa4Fixture) (vAsset, vToken string) {
	t.Helper()
	contract := [32]byte{7}
	prevout := [32]byte{9}
	issue := &elements.Tx{Version: 2}
	issue.In = append(issue.In, &elements.TxIn{
		Prevout: elements.OutPoint{Hash: prevout, N: 2},
		Issuance: &elements.AssetIssuance{
			Entropy: contract, Amount: elements.ExplicitValue(1), InflationKeys: elements.ExplicitValue(1_0000_0000),
		},
	})
	issue.NormalizeWitness()
	f.node.rawTxs[issue.TxID()] = hex.EncodeToString(issue.Serialize())
	_, a, tok := fastmerkle.DeriveIssuanceIDs(prevout, 2, contract)
	vAsset, vToken = displayHash(a), displayHash(tok)
	if err := f.st.Update(func(s *store.State) error {
		a := s.Assets[f.asset.ID]
		a.Enforcement = "damp"
		a.Damp = &store.DampBinding{
			VerifierAsset: vAsset, VerifierAmount: 1, VerifierIssueTxid: issue.TxID(),
			IssuerUpdateKey: testColdKey, VerifierSPK: "5120" + strings.Repeat("ab", 32),
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return vAsset, vToken
}

// TestVerifierToken_MoveAnIssuedToken: an asset issued before V's token went
// straight into its covenant moves it there from the wallet, explicitly,
// recording the asset's current verifier; a second request moves nothing.
func TestVerifierToken_MoveAnIssuedToken(t *testing.T) {
	f := newOA4Fixture(t)
	tool := withFakeCapTool(f.s)
	_, vToken := dampVerifierFixture(t, f)
	f.node.confUnspent = append(f.node.confUnspent, rpc.ConfUnspent{
		TxID: strings.Repeat("aa", 32), Vout: 1, ScriptPubKey: "0014" + strings.Repeat("dd", 20),
		Amount: 1.0, Asset: vToken, Spendable: true,
	})
	code, out := postJSON(t, f.s.handleVerifierTokenMove, "/v1/issuer/verifier-token", map[string]any{"asset": f.asset.ID})
	if code != 200 || out["status"] != "moved" {
		t.Fatalf("move: %d %v", code, out)
	}
	var vt *store.VerifierToken
	f.st.View(func(s *store.State) { vt = s.Assets[f.asset.ID].Damp.VerifierToken })
	if vt == nil || vt.Recorded != "5120"+strings.Repeat("ab", 32) || vt.Token != vToken {
		t.Fatalf("not recorded: %+v", vt)
	}
	sent, _ := elements.DeserializeTx(mustHexBytes(f.node.lastBroadcast))
	if hex.EncodeToString(sent.Out[0].ScriptPubKey) != vt.ScriptPubKey || len(sent.Out[0].Nonce) != 1 {
		t.Fatalf("the token output does not pay the covenant explicitly: %x", sent.Out[0].ScriptPubKey)
	}
	if amt, _ := elements.ExplicitValueAmount(sent.Out[0].Value); amt != 1_0000_0000 || vt.TokenAtoms != amt || vt.IssuedTokenAtoms != amt {
		t.Fatalf("moved %d, recorded %+v", amt, vt)
	}
	// The instance names the asset's issuer update key and the verifier it records.
	var instanceCall []string
	for _, c := range tool.calls {
		if len(c) > 1 && c[0] == "verifier-token" && c[1] == "instance" {
			instanceCall = c
		}
	}
	if flagOf(instanceCall, "issuer-key") != testColdKey || flagOf(instanceCall, "verifier") != vt.Recorded ||
		flagOf(instanceCall, "amount") != "1" {
		t.Fatalf("instance derived from the wrong values: %v", instanceCall)
	}
	code, out = postJSON(t, f.s.handleVerifierTokenMove, "/v1/issuer/verifier-token", map[string]any{"asset": f.asset.ID})
	if code != 200 || out["status"] != "already in its covenant" || f.node.sends != 1 {
		t.Fatalf("second move: %d %v (sends %d)", code, out, f.node.sends)
	}
}

// TestVerifierToken_MoveRefusals: a co-signed asset has no verifier asset, and
// a wallet without the token has nothing to move; neither broadcasts.
func TestVerifierToken_MoveRefusals(t *testing.T) {
	f := newOA4Fixture(t)
	withFakeCapTool(f.s)
	code, out := postJSON(t, f.s.handleVerifierTokenMove, "/v1/issuer/verifier-token", map[string]any{"asset": f.asset.ID})
	if code != 409 || !strings.Contains(out["error"].(string), "not network-enforced") {
		t.Fatalf("cosign asset: %d %v", code, out)
	}
	dampVerifierFixture(t, f)
	code, out = postJSON(t, f.s.handleVerifierTokenMove, "/v1/issuer/verifier-token", map[string]any{"asset": f.asset.ID})
	if code != 409 || !strings.Contains(out["error"].(string), "holds no coin of V's token") {
		t.Fatalf("no token in the wallet: %d %v", code, out)
	}
	if f.node.sends != 0 {
		t.Fatalf("a refusal broadcast %d transactions", f.node.sends)
	}
}
