// Package treefake is a stand-in for arca-enclave in tests: a test binary
// runs itself as the tool (Main, from TestMain), so the server's exec path is
// the one the real tool takes. It builds nothing Arca builds: a board record is
// the hex of the answer the test wants, an input coin the hex of
// {"salt","holder","value"}, and every script and digest is a hash of what it
// was given, so a test can recompute what the server should have sent.
package treefake

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Env marks a process as the tool.
const Env = "OPENAMPD_FAKE_ARCA_ENCLAVE"

// Main runs the fake and exits when this process is the tool; otherwise it
// marks the environment so the processes the test starts are.
func Main() {
	if os.Getenv(Env) == "1" && len(os.Args) > 1 {
		os.Exit(Run(os.Args[1], os.Stdin, os.Stdout))
	}
	os.Setenv(Env, "1")
}

// Path is the tool's path: this test binary.
func Path() string {
	p, err := os.Executable()
	if err != nil {
		panic(err)
	}
	return p
}

// Coin is an input coin's record as the fake reads it.
type Coin struct {
	Salt   string `json:"salt"`
	Holder string `json:"holder"`
	Value  string `json:"value"`
	Error  string `json:"error,omitempty"`
}

// CoinHex is the record of a coin.
func CoinHex(c Coin) string {
	b, _ := json.Marshal(c)
	return hex.EncodeToString(b)
}

// BoardHex is a board record whose reading is answer.
func BoardHex(answer map[string]any) string {
	b, _ := json.Marshal(answer)
	return hex.EncodeToString(b)
}

func h(parts ...string) string {
	s := sha256.New()
	for _, p := range parts {
		s.Write([]byte(p))
		s.Write([]byte{0})
	}
	return hex.EncodeToString(s.Sum(nil))
}

// Request is the transfer request the server sends.
type Request struct {
	Genesis  string  `json:"genesis"`
	Operator string  `json:"operator"`
	Policy   string  `json:"policy"`
	Clawback *string `json:"clawback"`
	Inputs   []struct {
		Coin            string `json:"coin"`
		CheckpointValue string `json:"checkpoint_value"`
	} `json:"inputs"`
	Outputs []struct {
		Asset          string `json:"asset"`
		Value          string `json:"value"`
		Holder         string `json:"holder"`
		OwnerNonce     string `json:"owner_nonce"`
		CreatorNonce   string `json:"creator_nonce"`
		ExitDelayUnits int    `json:"exit_delay_units"`
	} `json:"outputs"`
}

// Terms is what every digest of a request commits to.
func (r *Request) Terms() string {
	c := "none"
	if r.Clawback != nil {
		c = *r.Clawback
	}
	return r.Genesis + "|" + r.Operator + "|" + r.Policy + "|" + c
}

// OutputScript is the fake script of an output leaf.
func OutputScript(holder, ownerNonce string) string { return "5120" + h("leaf", holder, ownerNonce) }

// Digests are an input's two digests in a request.
func Digests(r *Request, salt string) (string, string) {
	outs := ""
	for _, o := range r.Outputs {
		outs += o.Holder + ":" + o.Value + ":" + o.OwnerNonce + ";"
	}
	return h("checkpoint", salt, r.Terms()), h("reassignment", salt, r.Terms(), outs)
}

func fail(w io.Writer, msg string) int {
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
	return 1
}

// Run is the fake tool.
func Run(cmd string, in io.Reader, out io.Writer) int {
	body, _ := io.ReadAll(in)
	switch cmd {
	case "board":
		var req struct {
			Record string `json:"record"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			return fail(out, "no request")
		}
		raw, err := hex.DecodeString(req.Record)
		if err != nil {
			return fail(out, "the record is not hex")
		}
		var answer map[string]any
		if err := json.Unmarshal(raw, &answer); err != nil {
			return fail(out, "the record is no board record")
		}
		if e, ok := answer["error"].(string); ok {
			return fail(out, e)
		}
		json.NewEncoder(out).Encode(answer)
		return 0
	case "transfer":
		var r Request
		if err := json.Unmarshal(body, &r); err != nil {
			return fail(out, "no request")
		}
		type inAns struct {
			Salt               string `json:"salt"`
			Holder             string `json:"holder"`
			Value              string `json:"value"`
			CheckpointValue    string `json:"checkpoint_value"`
			CheckpointDigest   string `json:"checkpoint_digest"`
			ReassignmentDigest string `json:"reassignment_digest"`
		}
		type outAns struct {
			Salt         string  `json:"salt"`
			Holder       string  `json:"holder"`
			Value        string  `json:"value"`
			ScriptPubKey string  `json:"script_pubkey"`
			ClawControl  *string `json:"claw_control"`
		}
		var ins []inAns
		asset := ""
		for _, i := range r.Inputs {
			raw, err := hex.DecodeString(i.Coin)
			if err != nil {
				return fail(out, "a coin record is not hex")
			}
			var c Coin
			if err := json.Unmarshal(raw, &c); err != nil {
				return fail(out, "a coin record is no record")
			}
			if c.Error != "" {
				return fail(out, c.Error)
			}
			cd, rd := Digests(&r, c.Salt)
			ins = append(ins, inAns{Salt: c.Salt, Holder: c.Holder, Value: c.Value, CheckpointValue: i.CheckpointValue,
				CheckpointDigest: cd, ReassignmentDigest: rd})
		}
		var outs []outAns
		for _, o := range r.Outputs {
			asset = o.Asset
			var claw *string
			if r.Clawback != nil {
				c := "c5" + h("claw", o.Holder, o.OwnerNonce)
				claw = &c
			}
			outs = append(outs, outAns{Salt: o.OwnerNonce, Holder: o.Holder, Value: o.Value,
				ScriptPubKey: OutputScript(o.Holder, o.OwnerNonce), ClawControl: claw})
		}
		json.NewEncoder(out).Encode(map[string]any{"asset": asset, "inputs": ins, "outputs": outs})
		return 0
	}
	return fail(out, fmt.Sprintf("no command %q", cmd))
}
