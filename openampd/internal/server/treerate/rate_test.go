// Package treerate measures how fast openampd approves reassignments in an
// asset's tree, end to end: HTTP, the tool, the rules, the register and the
// policy signatures, with the local key and with the FROST 2-of-3 quorum.
// It runs only when asked, since it is a measurement and not a check:
//
//	OPENAMPD_TREE_RATE=1 go test -p 1 -run TestTreeRate -v ./openampd/internal/server/treerate
package treerate

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ConcatenaLabs/openamp/openampd/internal/elements"
	"github.com/ConcatenaLabs/openamp/openampd/internal/rpc"
	"github.com/ConcatenaLabs/openamp/openampd/internal/server"
	"github.com/ConcatenaLabs/openamp/openampd/internal/server/frostsigner"
	"github.com/ConcatenaLabs/openamp/openampd/internal/server/treefake"
	"github.com/ConcatenaLabs/openamp/openampd/internal/store"
)

func TestMain(m *testing.M) {
	treefake.Main()
	os.Exit(m.Run())
}

const token = "rate-token"

func xonly(t *testing.T) (string, []byte) {
	t.Helper()
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatal(err)
	}
	x := elements.XOnlyFromPriv(priv)
	return hex.EncodeToString(x[:]), priv
}

// node answers the few calls the approval path and New make.
func node(t *testing.T) *rpc.Client {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		var result any
		switch req.Method {
		case "getblockhash":
			result = strings.Repeat("ab", 32)
		case "scantxoutset":
			result = map[string]any{"success": true, "unspents": []any{}}
		case "listunspent":
			result = []any{}
		}
		json.NewEncoder(w).Encode(map[string]any{"result": result, "error": nil})
	}))
	t.Cleanup(ts.Close)
	c, err := rpc.New(ts.URL, "u:p")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type rig struct {
	url    string
	asset  string
	sender string // x-only
	other  string
	n      int // leaves seeded for the sender
}

// newRig is a server with the asset's tree enabled, n live leaves of one
// sender and extra unrelated leaves in the register, and the asset's policy key
// on the named backend.
func newRig(t *testing.T, backend string, n, extra int) *rig {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cl := node(t)
	srv, err := server.New(server.Config{IssuerToken: token, Signer: backend, ArcaEnclave: treefake.Path()}, st, cl, cl)
	if err != nil {
		t.Fatal(err)
	}
	assetID := strings.Repeat("5a", 32)
	var policy string
	switch backend {
	case "local":
		p, priv := xonly(t)
		policy = p
		if err := st.SaveKey("policy:"+assetID, hex.EncodeToString(priv)); err != nil {
			t.Fatal(err)
		}
	case "frost":
		f, err := frostsigner.New(st, frostsigner.Config{})
		if err != nil {
			t.Fatal(err)
		}
		pub, ref, err := f.GeneratePolicyKey()
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Adopt(ref, assetID); err != nil {
			t.Fatal(err)
		}
		policy = hex.EncodeToString(pub[:])
	}
	issuer, _ := xonly(t)
	sender, _ := xonly(t)
	other, _ := xonly(t)
	err = st.Update(func(s *store.State) error {
		for _, k := range []string{issuer, sender, other} {
			aid := store.AID([]string{k})
			s.Users[aid] = &store.User{AID: aid, Pubkeys: []string{k}}
		}
		s.Assets[assetID] = &store.Asset{ID: assetID, Ticker: "RATE", PolicyPub: policy, IssuerPub: issuer,
			IssuerAID: store.AID([]string{issuer}), Clawback: true,
			Rules: store.Rules{HolderCap: 100000, VelocityWindowBlocks: 144, VelocityMaxAtoms: 1 << 60}}
		s.Height = 100
		for i := 0; i < n+extra; i++ {
			holder := sender
			if i >= n {
				holder = other
			}
			salt := fmt.Sprintf("%064x", i+1)
			s.TreeLeaves[salt] = &store.TreeLeaf{Salt: salt, Asset: assetID, HolderAID: store.AID([]string{holder}),
				Holder: holder, Atoms: 1000, State: store.LeafLive, ExitScript: "5120" + salt, Height: -1,
				Scripts: []store.LeafScript{{ScriptPubKey: "5120" + salt}}}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Routes())
	t.Cleanup(ts.Close)
	r := &rig{url: ts.URL, asset: assetID, sender: sender, other: other, n: n}
	op, _ := xonly(t)
	if code, body := r.post(t, "/v1/issuer/tree", map[string]any{"asset": assetID, "operator": op}); code != 200 {
		t.Fatalf("enable: %d %s", code, body)
	}
	return r
}

func (r *rig) post(t *testing.T, path string, body any) (int, string) {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", r.url+path, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Error(err)
		return 0, ""
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

// approve spends the sender's leaf i: 100 to the other holder, 900 back.
func (r *rig) approve(t *testing.T, i int) {
	salt := fmt.Sprintf("%064x", i+1)
	body := map[string]any{"asset": r.asset, "transfer": map[string]any{
		"inputs": []any{map[string]any{"coin": treefake.CoinHex(treefake.Coin{Salt: salt, Holder: r.sender, Value: "1000"}),
			"checkpoint_value": "1000"}},
		"outputs": []any{
			map[string]any{"asset": r.asset, "value": "100", "holder": r.other, "owner_nonce": fmt.Sprintf("%064x", 1<<40+2*i),
				"creator_nonce": strings.Repeat("cc", 32), "exit_delay_units": 2},
			map[string]any{"asset": r.asset, "value": "900", "holder": r.sender, "owner_nonce": fmt.Sprintf("%064x", 1<<40+2*i+1),
				"creator_nonce": strings.Repeat("cc", 32), "exit_delay_units": 2},
		}}}
	code, out := r.post(t, "/v1/issuer/tree/transfer", body)
	if code != 200 || !strings.Contains(out, `"signatures"`) {
		t.Errorf("approval %d: %d %s", i, code, out)
	}
}

func measure(t *testing.T, r *rig, clients int) (float64, time.Duration) {
	t.Helper()
	start := time.Now()
	var wg sync.WaitGroup
	next := make(chan int, r.n)
	for i := 0; i < r.n; i++ {
		next <- i
	}
	close(next)
	for c := 0; c < clients; c++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				r.approve(t, i)
			}
		}()
	}
	wg.Wait()
	d := time.Since(start)
	return float64(r.n) / d.Seconds(), d / time.Duration(r.n)
}

func TestTreeRate(t *testing.T) {
	if os.Getenv("OPENAMPD_TREE_RATE") != "1" {
		t.Skip("a measurement: set OPENAMPD_TREE_RATE=1")
	}
	const n = 200
	for _, backend := range []string{"local", "frost"} {
		for _, extra := range []int{0, 5000} {
			for _, clients := range []int{1, 8} {
				r := newRig(t, backend, n, extra)
				rate, per := measure(t, r, clients)
				t.Logf("RATE backend=%s register=%d+%d leaves clients=%d: %d approvals in %.2fs, %.1f approvals/s, %.2f ms each (2 policy signatures per approval)",
					backend, n, extra, clients, n, float64(n)/rate, rate, float64(per.Microseconds())/1000)
			}
		}
	}

	// One tool exec: the stand-in tool (this test binary) against a no-op.
	in, _ := json.Marshal(map[string]any{"genesis": "", "operator": "", "policy": "", "clawback": nil,
		"inputs":  []any{map[string]any{"coin": treefake.CoinHex(treefake.Coin{Salt: "01", Holder: "02", Value: "1"}), "checkpoint_value": "1"}},
		"outputs": []any{map[string]any{"asset": "a", "value": "1", "holder": "02", "owner_nonce": "03", "creator_nonce": "04", "exit_delay_units": 1}}})
	timeExec := func(path string, args ...string) time.Duration {
		const k = 50
		start := time.Now()
		for i := 0; i < k; i++ {
			c := exec.Command(path, args...)
			c.Stdin = bytes.NewReader(in)
			if err := c.Run(); err != nil {
				t.Fatalf("%s: %v", path, err)
			}
		}
		return time.Since(start) / k
	}
	fake := timeExec(treefake.Path(), "transfer")
	noop := timeExec("/bin/true")
	t.Logf("EXEC the stand-in tool %.2f ms, /bin/true %.2f ms per exec", float64(fake.Microseconds())/1000, float64(noop.Microseconds())/1000)
}
