package server

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/ConcatenaLabs/openamp/openampd/internal/store"
)

// TestAssets_ListedInStableOrder: the listing is sorted by ticker, then id, so
// two calls agree and a client can diff them.
func TestAssets_ListedInStableOrder(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(s *store.State) error {
		for _, a := range []store.Asset{
			{ID: "cc", Ticker: "ZED"}, {ID: "bb", Ticker: "ALPHA"},
			{ID: "aa", Ticker: "MID"}, {ID: "dd", Ticker: "ALPHA"},
		} {
			cp := a
			s.Assets[a.ID] = &cp
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: Config{}, st: st}
	want := []string{"bb", "dd", "aa", "cc"}
	for i := 0; i < 20; i++ {
		rec := httptest.NewRecorder()
		s.handleAssets(rec, httptest.NewRequest("GET", "/v1/assets", nil))
		var out struct {
			Assets []store.Asset `json:"assets"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, a := range out.Assets {
			got = append(got, a.ID)
		}
		if len(got) != len(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		for j := range want {
			if got[j] != want[j] {
				t.Fatalf("call %d: got %v, want %v", i, got, want)
			}
		}
	}
}
