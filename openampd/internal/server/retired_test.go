package server

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ConcatenaLabs/openamp/openampd/internal/store"
)

// A co-sign that still names boards of an asset's tree is refused by name,
// whatever the list holds: a co-sign that silently left them out would sign a
// transaction its caller did not mean.
func TestCosignTreeOutputsRefused(t *testing.T) {
	s, _ := newM2Server(t, Config{})
	h := s.Routes()
	for _, path := range []string{"/v1/cosign", "/v1/check"} {
		for _, outs := range []string{`[{"output":0,"record":"00"}]`, `[]`, `null`} {
			body := `{"tx":"00","asset":"` + strings.Repeat("11", 32) + `","sender_aid":"x","tree_outputs":` + outs + `}`
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest("POST", path, bytes.NewBufferString(body)))
			if rec.Code != 400 || !strings.Contains(rec.Body.String(), EnclaveRetired) {
				t.Fatalf("%s with tree_outputs %s: %d %s", path, outs, rec.Code, rec.Body.String())
			}
		}
	}
	// Without the field the request goes on to the usual checks.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/cosign",
		bytes.NewBufferString(`{"tx":"00","asset":"`+strings.Repeat("11", 32)+`","sender_aid":"x"}`)))
	if strings.Contains(rec.Body.String(), EnclaveRetired) {
		t.Fatalf("a co-sign without tree_outputs got the retirement: %d %s", rec.Code, rec.Body.String())
	}
}

// Every route of an asset's tree answers 410 Gone with the retirement, with or
// without the issuer token, so an old client meets a named refusal.
func TestTreeRoutesGone(t *testing.T) {
	s, _ := newM2Server(t, Config{IssuerToken: "tok"})
	h := s.Routes()
	for _, path := range []string{
		"/v1/tree/leaves/" + strings.Repeat("ab", 32) + "/exited",
		"/v1/issuer/tree",
		"/v1/issuer/tree/transfer",
		"/v1/issuer/tree/transfer/some-id/drop",
		"/v1/issuer/tree/clawback",
	} {
		for _, auth := range []string{"", "Bearer tok"} {
			req := httptest.NewRequest("POST", path, bytes.NewBufferString(`{}`))
			if auth != "" {
				req.Header.Set("Authorization", auth)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			var body map[string]string
			_ = json.Unmarshal(rec.Body.Bytes(), &body)
			if rec.Code != 410 || body["error"] != EnclaveRetired {
				t.Fatalf("POST %s (auth %q): %d %s", path, auth, rec.Code, rec.Body.String())
			}
		}
	}
}

// A state document that still carries an asset's tree, its leaves and its
// transfers opens, and GET /v1/assets/{id} has no "tree" key: the keys are
// dropped on the next write, with no migration.
func TestStoredTreeIgnored(t *testing.T) {
	dir := t.TempDir()
	id := strings.Repeat("22", 32)
	doc := `{"users":{},"assets":{"` + id + `":{"id":"` + id + `","ticker":"OLD","tree":{"operator":"aa","policy":"bb","clawback":null}}},` +
		`"tree_leaves":{"cc":{"salt":"cc","asset":"` + id + `","atoms":5,"state":"live"}},` +
		`"tree_transfers":{"t1":{"id":"t1","asset":"` + id + `"}}}`
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir)
	if err != nil {
		t.Fatalf("a document with tree keys must open: %v", err)
	}
	s := &Server{st: st, pending: map[string]*pendingTransfer{}, signer: NewLocalKeySigner(st)}
	var found bool
	st.View(func(state *store.State) { _, found = state.Assets[id] })
	if !found {
		t.Fatal("the asset did not load")
	}
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, httptest.NewRequest("GET", "/v1/assets/"+id, nil))
	var view map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil || rec.Code != 200 {
		t.Fatalf("GET asset: %d %s", rec.Code, rec.Body.String())
	}
	if _, has := view["tree"]; has {
		t.Fatalf("GET asset still carries tree: %s", rec.Body.String())
	}
	if err := st.Update(func(*store.State) error { return nil }); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"tree"`, `"tree_leaves"`, `"tree_transfers"`} {
		if bytes.Contains(data, []byte(key)) {
			t.Fatalf("the next write kept %s", key)
		}
	}
}
