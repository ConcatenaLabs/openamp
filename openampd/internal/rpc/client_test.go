package rpc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeNode answers scantxoutset the way the node does: one scan at a time, and
// a second one while the first runs is refused with RPC error -8.
type fakeNode struct {
	busy     atomic.Bool
	external atomic.Int32 // refusals still to give as if another client were scanning
	scans    atomic.Int32
	refused  atomic.Int32
}

func (n *fakeNode) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     uint64 `json:"id"`
		Method string `json:"method"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	refuse := func() {
		n.refused.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": req.ID, "result": nil,
			"error": map[string]any{"code": -8, "message": `Scan already in progress, use action "abort" or "status"`}})
	}
	if n.external.Load() > 0 {
		n.external.Add(-1)
		refuse()
		return
	}
	if !n.busy.CompareAndSwap(false, true) {
		refuse()
		return
	}
	time.Sleep(20 * time.Millisecond)
	n.scans.Add(1)
	n.busy.Store(false)
	_ = json.NewEncoder(w).Encode(map[string]any{"id": req.ID, "error": nil,
		"result": map[string]any{"success": true, "unspents": []any{}}})
}

func TestScanTxOutSetConcurrent(t *testing.T) {
	node := &fakeNode{}
	srv := httptest.NewServer(node)
	defer srv.Close()
	// Two clients on the same node, one of them wallet-scoped: they share the lock.
	a, _ := New(srv.URL, "u:p")
	b, _ := New(srv.URL+"/wallet/watch", "u:p")
	const n = 15
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := range n {
		c := a
		if i%2 == 1 {
			c = b
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.ScanTxOutSet([]string{"0014aa"}); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent scan failed: %v", err)
	}
	if got := node.scans.Load(); got != n {
		t.Errorf("node ran %d scans, want %d", got, n)
	}
	if got := node.refused.Load(); got != 0 {
		t.Errorf("node refused %d scans from one process, want 0", got)
	}
}

func TestScanTxOutSetWaitsForOtherClient(t *testing.T) {
	node := &fakeNode{}
	node.external.Store(3)
	srv := httptest.NewServer(node)
	defer srv.Close()
	c, _ := New(srv.URL, "u:p")
	if _, err := c.ScanTxOutSet([]string{"0014aa"}); err != nil {
		t.Fatalf("scan behind another client's scan: %v", err)
	}
	if got := node.refused.Load(); got != 3 {
		t.Errorf("refused %d times, want 3", got)
	}
}

func TestScanTxOutSetGivesUpWhenNodeStaysBusy(t *testing.T) {
	old := scanBusyWait
	scanBusyWait = 200 * time.Millisecond
	defer func() { scanBusyWait = old }()
	node := &fakeNode{}
	node.external.Store(1 << 20)
	srv := httptest.NewServer(node)
	defer srv.Close()
	c, _ := New(srv.URL, "u:p")
	start := time.Now()
	_, err := c.ScanTxOutSet([]string{"0014aa"})
	if !IsRPCError(err, "Scan already in progress") {
		t.Fatalf("err = %v, want the node's busy error", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("gave up after %v, want about scanBusyWait", d)
	}
}
