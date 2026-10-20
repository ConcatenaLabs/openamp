package server

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"

	"github.com/ConcatenaLabs/openamp/openampd/internal/elements"
	"github.com/ConcatenaLabs/openamp/openampd/internal/store"
)

// Supply caps: the reissuance token of every asset this server issues lives in
// a covenant, never in the server's wallet.
//
// Whoever holds a reissuance token can mint any amount of its asset, so a token
// in the server wallet trusted that wallet's key with the whole supply. The
// supply cap (sequentia-contracts' templates/supply_cap, docs/supply-cap.md)
// holds the token in a Simplicity covenant instead: this server's operator key
// mints only while the total minted through the covenant stays at or under a
// cap fixed when the covenant is made, and a cold key kept off this server can
// move the covenant to new keys. No path takes the token out or raises the cap,
// so a compromise of this server mints at most the room left under the cap.
//
// A Go server cannot compile Simplicity, so the token-covenants tool from
// sequentia-contracts derives the covenant's addresses and builds and signs its
// spends. The tool reaches no node and holds no credential: this server hands it
// the coins as the transactions that made them and its operator key file, signs
// the fee coin with its wallet, and broadcasts.

// CovenantTool runs the token-covenants tool: arguments, a request on stdin,
// one JSON object on stdout. Tests substitute a fake.
type CovenantTool interface {
	Run(args []string, stdin []byte) ([]byte, error)
}

type execTool struct{ path string }

func (t execTool) Run(args []string, stdin []byte) ([]byte, error) {
	cmd := exec.Command(t.path, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, errors.New(msg)
	}
	return out.Bytes(), nil
}

// supplyCapNotConfigured is the refusal every path that needs the tool gives
// when -tokentool is unset.
const supplyCapNotConfigured = "supply caps are not configured on this policy server (-tokentool): an asset's reissuance token is never left in the server wallet, so it cannot be issued or minted without one"

var xonlyHex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ensureCapOperatorKey returns the x-only key of the operator key file at path,
// making the key on first use: 32 random bytes, hex, written once to a new file
// readable by this server's user alone. The secret is never logged.
func ensureCapOperatorKey(path string) (string, error) {
	text, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		priv, gerr := btcec.NewPrivateKey()
		if gerr != nil {
			return "", gerr
		}
		f, ferr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if ferr != nil {
			return "", ferr
		}
		if _, werr := f.WriteString(hex.EncodeToString(priv.Serialize()) + "\n"); werr != nil {
			f.Close()
			return "", werr
		}
		if serr := f.Sync(); serr != nil {
			f.Close()
			return "", serr
		}
		if cerr := f.Close(); cerr != nil {
			return "", cerr
		}
		text, err = os.ReadFile(path)
	}
	if err != nil {
		return "", err
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(text)))
	if err != nil || len(b) != 32 {
		return "", fmt.Errorf("%s: not a 32-byte hex secret key", path)
	}
	x := elements.XOnlyFromPriv(b)
	return hex.EncodeToString(x[:]), nil
}

// capReady writes the refusal and returns ok=false when this server cannot put
// a token into a supply cap; otherwise it returns the cold key to use: the
// request's, else the server's default. The cold key must be a curve point and
// another key than this server's operator key, or it could not replace it.
func (s *Server) capReady(w http.ResponseWriter, requested string) (string, bool) {
	if s.tool == nil {
		httpErr(w, 501, supplyCapNotConfigured)
		return "", false
	}
	cold := strings.ToLower(requested)
	if cold == "" {
		cold = strings.ToLower(s.cfg.CapColdKey)
	}
	if cold == "" {
		httpErr(w, 400, "cap_cold_key is required: no default cold key is configured (-capcoldkey). The cold key replaces a lost operator key and is kept off this server")
		return "", false
	}
	if !xonlyHex.MatchString(cold) {
		httpErr(w, 400, "cap_cold_key must be 32-byte x-only hex")
		return "", false
	}
	if _, err := schnorr.ParsePubKey(mustHexBytes(cold)); err != nil {
		httpErr(w, 400, "cap_cold_key is not a valid x-only public key: %v", err)
		return "", false
	}
	if cold == s.capOperatorKey {
		httpErr(w, 400, "cap_cold_key is this server's operator key: the cold key must be one this server does not hold")
		return "", false
	}
	return cold, true
}

// runTool runs one tool command and decodes its JSON reply into out.
func (s *Server) runTool(out any, request any, args ...string) error {
	var stdin []byte
	if request != nil {
		b, err := json.Marshal(request)
		if err != nil {
			return err
		}
		stdin = b
	}
	raw, err := s.tool.Run(args, stdin)
	if err != nil {
		return fmt.Errorf("token-covenants %s: %w", strings.Join(args[:min(2, len(args))], " "), err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("token-covenants %s: unreadable reply: %w", strings.Join(args[:min(2, len(args))], " "), err)
	}
	return nil
}

// withInstance writes an instance file for one tool call and removes it after.
func (s *Server) withInstance(instance json.RawMessage, fn func(path string) error) error {
	dir := os.TempDir()
	if s.st != nil {
		dir = s.st.Dir()
	}
	f, err := os.CreateTemp(dir, "supply-cap-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(instance); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return fn(f.Name())
}

type toolAddress struct {
	ScriptPubKey string            `json:"script_pubkey"`
	Address      map[string]string `json:"address"`
}

// capAddress is the instance's script and address while it holds `minted`.
func (s *Server) capAddress(instance json.RawMessage, minted uint64) (spk []byte, addr string, err error) {
	var a toolAddress
	err = s.withInstance(instance, func(path string) error {
		return s.runTool(&a, nil, "supply-cap", "address", "--instance", path, "--minted", strconv.FormatUint(minted, 10))
	})
	if err != nil {
		return nil, "", err
	}
	spk, err = hex.DecodeString(a.ScriptPubKey)
	if err != nil || len(spk) != 34 {
		return nil, "", fmt.Errorf("token-covenants supply-cap address: bad script_pubkey %q", a.ScriptPubKey)
	}
	return spk, s.chainAddress(spk, a.Address), nil
}

// chainAddress is the node's encoding of spk, or the tool's for this chain.
func (s *Server) chainAddress(spk []byte, byChain map[string]string) string {
	if a := s.addressOfSPK(spk); a != "" {
		return a
	}
	if a, ok := byChain["sequentia-testnet"]; ok && displayHash(s.genesis) == sequentiaTestnetGenesis {
		return a
	}
	return byChain["elementsregtest"]
}

const sequentiaTestnetGenesis = "ddd11d54c87a2bd94400fd31ce05d8e1110bb4b78e7103f738342086fc4ea92e"

// newSupplyCap derives the supply cap for an asset, with nothing minted: the
// address its token moves into. Ids and entropy are display hex.
func (s *Server) newSupplyCap(assetDisplay, tokenDisplay, entropyDisplay, coldKey string, cap uint64) (*store.SupplyCap, []byte, error) {
	var inst map[string]json.RawMessage
	if err := s.runTool(&inst, nil, "supply-cap", "instance",
		"--asset", assetDisplay, "--token", tokenDisplay, "--entropy", entropyDisplay,
		"--operator-key", s.capOperatorKey, "--cold-key", coldKey,
		"--cap", strconv.FormatUint(cap, 10), "--genesis", displayHash(s.genesis)); err != nil {
		return nil, nil, err
	}
	delete(inst, "address") // for convenience only; not part of the instance file
	file, err := json.Marshal(inst)
	if err != nil {
		return nil, nil, err
	}
	spk, addr, err := s.capAddress(file, 0)
	if err != nil {
		return nil, nil, err
	}
	return &store.SupplyCap{
		Instance: file, Cap: cap, OperatorKey: s.capOperatorKey, ColdKey: coldKey,
		ScriptPubKey: hex.EncodeToString(spk), Address: addr,
	}, spk, nil
}

// rawTxHex is a transaction's raw hex: the node's, else the explorer's.
func (s *Server) rawTxHex(txid string) (string, error) {
	raw, err := s.node.GetRawTransactionHex(txid)
	if err == nil {
		return raw, nil
	}
	if raw, eerr := s.rawTxViaElectrs(txid); eerr == nil {
		return raw, nil
	}
	return "", fmt.Errorf("transaction %s: %w", txid, err)
}

// issuedTokenAtoms reads, from the asset's issuance transaction, how much of
// its reissuance token the issuance created; 0 when it cannot tell.
func (s *Server) issuedTokenAtoms(asset *store.Asset) uint64 {
	if asset.IssueTxid == "" || asset.Entropy == "" {
		return 0
	}
	raw, err := s.rawTxHex(asset.IssueTxid)
	if err != nil {
		return 0
	}
	tx, err := elements.DeserializeTx(mustHexBytes(raw))
	if err != nil {
		return 0
	}
	for _, in := range tx.In {
		if in.Issuance == nil || in.Issuance.Nonce != ([32]byte{}) {
			continue // no issuance, or a reissuance
		}
		if n, ok := elements.ExplicitValueAmount(in.Issuance.InflationKeys); ok {
			return n
		}
	}
	return 0
}

// supplyCapView is what the supply and asset reads show of a supply cap.
func supplyCapView(c *store.SupplyCap) map[string]any {
	if c == nil {
		return nil
	}
	room := uint64(0)
	if c.Cap > c.Minted {
		room = c.Cap - c.Minted
	}
	v := map[string]any{
		"cap_atoms": c.Cap, "minted_atoms": c.Minted, "room_atoms": room,
		"address": c.Address, "script_pubkey": c.ScriptPubKey,
		"coin": fmt.Sprintf("%s:%d", c.CoinTxid, c.CoinVout), "token_atoms": c.TokenAtoms,
		"operator_key": c.OperatorKey, "cold_key": c.ColdKey,
	}
	if c.IssuedTokenAtoms != 0 {
		v["issued_token_atoms"] = c.IssuedTokenAtoms
		v["holds_the_whole_token"] = c.TokenAtoms == c.IssuedTokenAtoms
	}
	return v
}

// --- the mint ----------------------------------------------------------------

type capBuild struct {
	Txid       string `json:"txid"`
	Hex        string `json:"hex"`
	NextMinted string `json:"next_minted"`
	Successor  struct {
		Vout         uint32            `json:"vout"`
		Amount       string            `json:"amount"`
		ScriptPubKey string            `json:"script_pubkey"`
		Address      map[string]string `json:"address"`
	} `json:"successor"`
	NextInstance json.RawMessage `json:"next_instance"`
}

// capMintTx builds and signs a mint of `atoms` through the asset's supply cap
// into targetSpk, the fee paid from an explicit wallet coin of the asset the
// fee rule chooses (feeasset.go).
// It returns the transaction with the fee coin signed and what the covenant's
// next coin will be. Nothing is broadcast.
func (s *Server) capMintTx(asset *store.Asset, targetSpk []byte, atoms uint64) (string, *capBuild, error) {
	c := asset.SupplyCap
	coinHex, err := s.rawTxHex(c.CoinTxid)
	if err != nil {
		return "", nil, err
	}
	feeIn, err := s.feeUTXO(2)
	if nf, ok := err.(*NoFeeCoin); ok {
		return "", nil, refuse("%s", nf.Reason)
	}
	if err != nil {
		return "", nil, fmt.Errorf("fee funding: %w", err)
	}
	feeHex, err := s.rawTxHex(feeIn.txid)
	if err != nil {
		return "", nil, err
	}
	changeAddr, err := s.wallet.GetNewAddress()
	if err != nil {
		return "", nil, err
	}
	changeSpk, err := s.addressScriptPubKey(changeAddr)
	if err != nil {
		return "", nil, err
	}
	req := map[string]any{
		"path": "mint", "coin": map[string]any{"tx": coinHex, "vout": c.CoinVout},
		"minted": strconv.FormatUint(c.Minted, 10), "entropy": asset.Entropy,
		"amount": strconv.FormatUint(atoms, 10), "mint_to": hex.EncodeToString(targetSpk),
		"fee": map[string]any{
			"coins":     []any{map[string]any{"tx": feeHex, "vout": feeIn.vout}},
			"atoms":     strconv.FormatUint(feeIn.fee, 10),
			"change_to": changeSpk,
		},
	}
	var b capBuild
	err = s.withInstance(c.Instance, func(path string) error {
		return s.runTool(&b, req, "supply-cap", "build", "--instance", path, "--key-file", s.capOperatorKeyFile)
	})
	if err != nil {
		return "", nil, err
	}
	signed, err := s.wallet.SignRawTransactionWithWallet(b.Hex)
	if err != nil {
		return "", nil, fmt.Errorf("sign the fee coin: %w", err)
	}
	if !signed.Complete {
		return "", nil, fmt.Errorf("fee coin signing incomplete: %+v", signed.Errors)
	}
	return signed.Hex, &b, nil
}

// --- moving a token in -------------------------------------------------------

// handleSupplyCapMove is POST /v1/issuer/supply-cap: move an issued asset's
// reissuance token out of this server's wallet into a supply cap, for an asset
// issued before its token went straight into one. Every coin of the token the
// wallet holds moves, in one transaction, to the instance with nothing minted.
// Pasting it again for an asset already moved answers with its supply cap.
//
// An asset issued before this server recorded its issuance entropy and token id
// names them in the request (the node wallet's `listissuances` shows both); the
// tool refuses an entropy that does not derive the asset and its token, and the
// record keeps them, so the asset can be minted again.
func (s *Server) handleSupplyCapMove(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Asset      string  `json:"asset"`
		Cap        *uint64 `json:"cap"`
		CapColdKey string  `json:"cap_cold_key"`
		Token      string  `json:"token"`
		Entropy    string  `json:"entropy"`
	}
	if err := decodeBody(r, &req); err != nil {
		httpErr(w, 400, "%v", err)
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
		httpErr(w, 404, "unknown asset")
		return
	}
	if asset.SupplyCap != nil {
		httpJSON(w, map[string]any{"asset": asset.ID, "status": "already in its supply cap",
			"supply_cap": supplyCapView(asset.SupplyCap)})
		return
	}
	if req.Cap == nil {
		httpErr(w, 400, "cap is required: the most ever minted through the covenant, in atoms (0: no further mint)")
		return
	}
	if asset.Entropy == "" || asset.Token == "" {
		if req.Token == "" || req.Entropy == "" {
			httpErr(w, 409, "this asset's issuance entropy and token id were not recorded: name them (token, entropy), as the node wallet's listissuances shows them")
			return
		}
		if !xonlyHex.MatchString(strings.ToLower(req.Token)) || !xonlyHex.MatchString(strings.ToLower(req.Entropy)) {
			httpErr(w, 400, "token and entropy are 32-byte hex")
			return
		}
		asset.Token, asset.Entropy = strings.ToLower(req.Token), strings.ToLower(req.Entropy)
	}
	cold, ok := s.capReady(w, req.CapColdKey)
	if !ok {
		return
	}
	all, err := s.wallet.ListUnspentAll()
	if err != nil {
		httpErr(w, 502, "list wallet coins: %v", err)
		return
	}
	var tokens []rpcConfLite
	var total uint64
	blinded := false
	for _, u := range all {
		if u.Asset == asset.Token && u.Spendable {
			tokens = append(tokens, rpcConfLite{u.TxID, u.Vout, sats(u.Amount)})
			total += sats(u.Amount)
			blinded = blinded || u.Blinded()
		}
	}
	if len(tokens) == 0 {
		httpErr(w, 409, "the server wallet holds no coin of the token %s: it moved already, or it was never here", asset.Token)
		return
	}
	cap, spk, err := s.newSupplyCap(asset.ID, asset.Token, asset.Entropy, cold, *req.Cap)
	if err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	feeIn, err := s.feeUTXO(3)
	if err != nil {
		httpErr(w, feeStatus(err), "fee funding: %v", err)
		return
	}
	feeAssetID := elements.MustHex32(feeIn.asset)
	tx := &elements.Tx{Version: 2}
	for _, t := range tokens {
		tx.In = append(tx.In, &elements.TxIn{Prevout: elements.OutPoint{Hash: internalHash(t.txid), N: t.vout}})
	}
	tx.In = append(tx.In, &elements.TxIn{Prevout: elements.OutPoint{Hash: internalHash(feeIn.txid), N: feeIn.vout}})
	// The token, explicitly and with no nonce: the covenant reads only explicit coins.
	tx.Out = append(tx.Out, &elements.TxOut{Asset: elements.ExplicitAsset(elements.MustHex32(asset.Token)),
		Value: elements.ExplicitValue(total), Nonce: elements.NullNonce(), ScriptPubKey: spk})
	// The fee change: blinded only when a token coin was, to balance its blinders.
	changeNonce, changeSpk := elements.NullNonce(), []byte(nil)
	if blinded {
		changeNonce, changeSpk, err = s.blindedWalletOutput()
	} else {
		var addr, spkHex string
		if addr, err = s.wallet.GetNewAddress(); err == nil {
			spkHex, err = s.addressScriptPubKey(addr)
			changeSpk = mustHexBytes(spkHex)
		}
	}
	if err != nil {
		httpErr(w, 502, "fee change output: %v", err)
		return
	}
	tx.Out = append(tx.Out,
		&elements.TxOut{Asset: elements.ExplicitAsset(feeAssetID), Value: elements.ExplicitValue(feeIn.sats - feeIn.fee),
			Nonce: changeNonce, ScriptPubKey: changeSpk},
		&elements.TxOut{Asset: elements.ExplicitAsset(feeAssetID), Value: elements.ExplicitValue(feeIn.fee),
			Nonce: elements.NullNonce(), ScriptPubKey: nil},
	)
	tx.NormalizeWitness()
	if blinded {
		if tx, err = s.blindTx(tx); err != nil {
			httpErr(w, 500, "blind the fee change: %v", err)
			return
		}
	}
	signed, err := s.wallet.SignRawTransactionWithWallet(hex.EncodeToString(tx.Serialize()))
	if err != nil {
		httpErr(w, 502, "sign: %v", err)
		return
	}
	if !signed.Complete {
		httpErr(w, 502, "move signing incomplete: %+v", signed.Errors)
		return
	}
	if err := s.mempoolGate("supply-cap-move", signed.Hex, map[string]any{"asset": asset.ID}); err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	txid, err := s.wallet.SendRawTransaction(signed.Hex)
	if err != nil {
		httpErr(w, 502, "broadcast: %v", err)
		return
	}
	cap.CoinTxid, cap.CoinVout, cap.TokenAtoms = txid, 0, total
	cap.IssuedTokenAtoms = s.issuedTokenAtoms(asset)
	if err := s.st.Update(func(st *store.State) error {
		a := st.Assets[asset.ID]
		a.SupplyCap = cap
		a.Token, a.Entropy = asset.Token, asset.Entropy
		return nil
	}); err != nil {
		httpErr(w, 500, "persist supply cap: %v", err)
		return
	}
	s.st.AppendLog("supply-cap-move", map[string]any{
		"asset": asset.ID, "txid": txid, "cap": cap.Cap, "token_atoms": total,
		"address": cap.Address, "operator_key": cap.OperatorKey, "cold_key": cap.ColdKey,
	})
	httpJSON(w, map[string]any{"asset": asset.ID, "status": "moved", "txid": txid,
		"supply_cap": supplyCapView(cap)})
}

type rpcConfLite struct {
	txid string
	vout uint32
	sats uint64
}

// --- adopting a rekey --------------------------------------------------------

// handleSupplyCapRekey is POST /v1/issuer/supply-cap/rekey: the cold key moved
// an asset's supply cap to new keys, off this server; this records the
// transaction that did it, once `token-covenants supply-cap follow` confirms it
// spent the recorded coin into the instance under the keys named.
func (s *Server) handleSupplyCapRekey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Asset          string `json:"asset"`
		Txid           string `json:"txid"`
		NewOperatorKey string `json:"new_operator_key"`
		NewColdKey     string `json:"new_cold_key"`
	}
	if err := decodeBody(r, &req); err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	if s.tool == nil {
		httpErr(w, 501, supplyCapNotConfigured)
		return
	}
	var asset *store.Asset
	s.st.View(func(st *store.State) {
		if a, ok := st.Assets[req.Asset]; ok {
			cp := *a
			asset = &cp
		}
	})
	if asset == nil || asset.SupplyCap == nil {
		httpErr(w, 404, "unknown asset, or its token is in no supply cap")
		return
	}
	c := asset.SupplyCap
	coinHex, err := s.rawTxHex(c.CoinTxid)
	if err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	spendHex, err := s.rawTxHex(req.Txid)
	if err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	var f struct {
		Path         string          `json:"path"`
		NextInstance json.RawMessage `json:"next_instance"`
	}
	err = s.withInstance(c.Instance, func(path string) error {
		return s.runTool(&f, map[string]any{
			"coin": map[string]any{"tx": coinHex, "vout": c.CoinVout}, "minted": strconv.FormatUint(c.Minted, 10),
			"tx": spendHex, "new_operator_key": req.NewOperatorKey, "new_cold_key": req.NewColdKey,
		}, "supply-cap", "follow", "--instance", path)
	})
	if err != nil {
		httpErr(w, 409, "%v", err)
		return
	}
	if f.Path != "rekey" || len(f.NextInstance) == 0 {
		httpErr(w, 409, "transaction %s spent the supply cap by its %s path, not a rekey to the keys named", req.Txid, f.Path)
		return
	}
	var inst map[string]json.RawMessage
	if err := json.Unmarshal(f.NextInstance, &inst); err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	delete(inst, "address")
	file, _ := json.Marshal(inst)
	spk, addr, err := s.capAddress(file, c.Minted)
	if err != nil {
		httpErr(w, 502, "%v", err)
		return
	}
	next := *c
	next.Instance, next.OperatorKey, next.ColdKey = file, strings.ToLower(req.NewOperatorKey), strings.ToLower(req.NewColdKey)
	next.CoinTxid, next.CoinVout, next.ScriptPubKey, next.Address = req.Txid, 0, hex.EncodeToString(spk), addr
	if err := s.st.Update(func(st *store.State) error {
		st.Assets[asset.ID].SupplyCap = &next
		return nil
	}); err != nil {
		httpErr(w, 500, "%v", err)
		return
	}
	s.st.AppendLog("supply-cap-rekey", map[string]any{"asset": asset.ID, "txid": req.Txid,
		"operator_key": next.OperatorKey, "cold_key": next.ColdKey})
	resp := map[string]any{"asset": asset.ID, "status": "rekeyed", "supply_cap": supplyCapView(&next)}
	if next.OperatorKey != s.capOperatorKey {
		resp["note"] = "the new operator key is not this server's, so this server cannot mint through the covenant"
	}
	httpJSON(w, resp)
}

// capOperatorKeyPath is where the operator key file lives by default.
func capOperatorKeyPath(dir string) string { return filepath.Join(dir, "cap-operator.key") }
