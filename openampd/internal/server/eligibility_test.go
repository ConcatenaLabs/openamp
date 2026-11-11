package server

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ConcatenaLabs/openamp/openampd/internal/damp"
	"github.com/ConcatenaLabs/openamp/openampd/internal/store"
)

// putAsset stores an asset so the handlers can find it by id.
func putAsset(t *testing.T, st *store.Store, a *store.Asset) {
	t.Helper()
	if err := st.Update(func(s *store.State) error {
		cp := *a
		s.Assets[a.ID] = &cp
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func getEligibility(t *testing.T, s *Server, params map[string]string) (int, eligibility, string) {
	t.Helper()
	q := url.Values{}
	for k, v := range params {
		q.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.handleEligibility(rec, httptest.NewRequest("GET", "/v1/eligibility?"+q.Encode(), nil))
	var out eligibility
	if rec.Code == 200 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode %s: %v", rec.Body.String(), err)
		}
	}
	return rec.Code, out, rec.Body.String()
}

func mustEligible(t *testing.T, s *Server, params map[string]string) {
	t.Helper()
	code, out, body := getEligibility(t, s, params)
	if code != 200 || !out.Eligible {
		t.Fatalf("want eligible, got %d %s", code, body)
	}
	if out.Onboarding != nil {
		t.Fatalf("an eligible answer carries no onboarding: %s", body)
	}
}

func mustRefuse(t *testing.T, s *Server, params map[string]string, wantCode string) eligibility {
	t.Helper()
	code, out, body := getEligibility(t, s, params)
	if code != 200 {
		t.Fatalf("a refusal is an answer (200), got %d %s", code, body)
	}
	if out.Eligible || out.Code != wantCode || out.Reason == "" {
		t.Fatalf("want refusal %q with a reason, got %s", wantCode, body)
	}
	return out
}

// The co-signed asset: registration, freezes, categories, the lock-in, and the
// way to be approved when refused.
func TestEligibility_Cosign(t *testing.T) {
	s, st, _ := newOA3Server(t)
	issuer := regUser(t, st, nil)
	approved := regUser(t, st, []string{"kyc:eu"})
	noCategory := regUser(t, st, nil)
	frozen := regUser(t, st, []string{"kyc:eu"})
	if err := st.Update(func(x *store.State) error { x.Users[frozen.AID].Frozen = true; return nil }); err != nil {
		t.Fatal(err)
	}
	setHeight(t, st, 500)
	asset := oa3Asset(t, issuer.AID, store.Rules{AllowedCategories: []string{"kyc:eu"}})
	asset.Contract = json.RawMessage(`{"entity":{"domain":"bonds.example"},"ticker":"OA3T"}`)
	putAsset(t, st, asset)

	mustEligible(t, s, map[string]string{"asset": asset.ID, "aid": approved.AID})
	// The key alone names the same account.
	mustEligible(t, s, map[string]string{"asset": asset.ID, "key": approved.Pubkeys[0]})

	out := mustRefuse(t, s, map[string]string{"asset": asset.ID, "aid": noCategory.AID}, "category")
	// No page set by the issuer: the contract's domain is the way forward.
	if out.Onboarding == nil || out.Onboarding.URL != "https://bonds.example" {
		t.Fatalf("want the contract's domain as onboarding, got %+v", out.Onboarding)
	}
	mustRefuse(t, s, map[string]string{"asset": asset.ID, "aid": frozen.AID}, "frozen")
	unknown := strings.Repeat("ab", 20)
	mustRefuse(t, s, map[string]string{"asset": asset.ID, "aid": unknown}, "unregistered")

	// A lock-in binds every secondary sale, whoever sells.
	locked := oa3Asset(t, issuer.AID, store.Rules{LockinUntilHeight: 1000})
	locked.ID = strings.Repeat("12", 32)
	putAsset(t, st, locked)
	mustRefuse(t, s, map[string]string{"asset": locked.ID, "aid": approved.AID}, "lockin")
	setHeight(t, st, 1000)
	mustEligible(t, s, map[string]string{"asset": locked.ID, "aid": approved.AID})
}

// The issuer's own page wins over the contract's domain, and the issuer can set,
// change and clear it.
func TestEligibility_OnboardingSetByIssuer(t *testing.T) {
	s, st, _ := newOA3Server(t)
	issuer := regUser(t, st, nil)
	buyer := regUser(t, st, nil)
	asset := oa3Asset(t, issuer.AID, store.Rules{AllowedCategories: []string{"kyc:eu"}})
	asset.Contract = json.RawMessage(`{"entity":{"domain":"bonds.example"}}`)
	putAsset(t, st, asset)

	post := func(body string) int {
		rec := httptest.NewRecorder()
		s.handleOnboarding(rec, httptest.NewRequest("POST", "/v1/issuer/onboarding", bytes.NewBufferString(body)))
		return rec.Code
	}
	for _, bad := range []string{
		`{"asset":"` + asset.ID + `","url":"javascript:alert(1)"}`,
		`{"asset":"` + asset.ID + `","url":"ftp://bonds.example/x"}`,
		`{"asset":"` + asset.ID + `","url":"https://"}`,
		`{"asset":"` + asset.ID + `","url":"https://a.example","name":"` + strings.Repeat("n", 101) + `"}`,
	} {
		if c := post(bad); c != 400 {
			t.Fatalf("want 400 for %s, got %d", bad, c)
		}
	}
	if c := post(`{"asset":"` + strings.Repeat("99", 32) + `","url":"https://a.example"}`); c != 404 {
		t.Fatalf("want 404 for an unknown asset, got %d", c)
	}
	if c := post(`{"asset":"` + asset.ID + `","name":"Bond Issuer Ltd","url":"https://bonds.example/investors/apply"}`); c != 200 {
		t.Fatalf("set: %d", c)
	}
	out := mustRefuse(t, s, map[string]string{"asset": asset.ID, "aid": buyer.AID}, "category")
	if out.Onboarding == nil || out.Onboarding.Name != "Bond Issuer Ltd" || out.Onboarding.URL != "https://bonds.example/investors/apply" {
		t.Fatalf("want the issuer's page, got %+v", out.Onboarding)
	}
	// It is public on the asset's record too.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/v1/assets/"+asset.ID, nil)
	req.SetPathValue("id", asset.ID)
	s.handleAsset(rec, req)
	if !strings.Contains(rec.Body.String(), "investors/apply") {
		t.Fatalf("asset record lacks onboarding: %s", rec.Body.String())
	}
	if c := post(`{"asset":"` + asset.ID + `","url":""}`); c != 200 {
		t.Fatalf("clear: %d", c)
	}
	out = mustRefuse(t, s, map[string]string{"asset": asset.ID, "aid": buyer.AID}, "category")
	if out.Onboarding == nil || out.Onboarding.URL != "https://bonds.example" {
		t.Fatalf("after clearing, want the contract's domain, got %+v", out.Onboarding)
	}
}

// Rules that read the chain (the holder cap) and rules that depend on one
// sender's history (velocity) answer as a co-sign would.
func TestEligibility_HolderCapAndSender(t *testing.T) {
	s, st, scan := newOA3Server(t)
	issuer := regUser(t, st, nil)
	holder := regUser(t, st, nil)
	newcomer := regUser(t, st, nil)
	setHeight(t, st, 500)
	asset := oa3Asset(t, issuer.AID, store.Rules{HolderCap: 1, VelocityMaxAtoms: 100, VelocityWindowBlocks: 10})
	putAsset(t, st, asset)
	*scan = []map[string]any{balanceUTXO(enclaveSpk(t, s, holder, asset), asset.ID)}

	mustRefuse(t, s, map[string]string{"asset": asset.ID, "aid": newcomer.AID}, "holder_cap")
	// The one holder may receive more: the count does not grow.
	mustEligible(t, s, map[string]string{"asset": asset.ID, "aid": holder.AID})

	// A seller whose window is spent cannot sell, though the buyer is eligible.
	if err := st.Update(func(x *store.State) error {
		x.Transfers = append(x.Transfers, store.TransferRecord{Asset: asset.ID, SenderAID: holder.AID, Atoms: 100, Height: 499})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	mustEligible(t, s, map[string]string{"asset": asset.ID, "aid": holder.AID, "atoms": "50"})
	// A seller with room in its window may sell to the holder.
	mustEligible(t, s, map[string]string{"asset": asset.ID, "aid": holder.AID, "atoms": "50", "from": newcomer.AID})
	asset.Rules.HolderCap = 0
	putAsset(t, st, asset)
	mustRefuse(t, s, map[string]string{"asset": asset.ID, "aid": newcomer.AID, "atoms": "50", "from": holder.AID}, "velocity")
}

// The answer is the co-sign's answer: a refusal here is the refusal a real
// transfer to the same party gets, from the same code.
func TestEligibility_MatchesCosignDecision(t *testing.T) {
	s, st, _ := newOA3Server(t)
	issuer := regUser(t, st, nil)
	seller := regUser(t, st, []string{"kyc:eu"})
	buyer := regUser(t, st, []string{"kyc:us"})
	setHeight(t, st, 500)
	for i, rules := range []store.Rules{
		{AllowedCategories: []string{"kyc:eu"}},
		{CategoryDenies: []store.CategoryDeny{{Prefix: "kyc:us", UntilHeight: 900}}},
		{LockinUntilHeight: 900},
	} {
		asset := oa3Asset(t, issuer.AID, rules)
		asset.ID = strings.Repeat(string("abcdef"[i])+"1", 32)
		putAsset(t, st, asset)
		out := mustRefuse(t, s, map[string]string{"asset": asset.ID, "aid": buyer.AID}, []string{"category", "category_denied", "lockin"}[i])
		err := s.checkTransfer(txTo(t, s, asset, 1, buyer), asset, seller, map[string]uint64{})
		pr, ok := err.(*PolicyRefusal)
		if !ok || pr.Code != out.Code || pr.Reason != out.Reason {
			t.Fatalf("rules %d: eligibility said %q/%q, the transfer check said %v", i, out.Code, out.Reason, err)
		}
	}
}

// The network-enforced asset: the whitelist, the receive window, the transfer
// limit and the seller's own entry, all from the current policy.
func TestEligibility_Damp(t *testing.T) {
	s, st, _ := newOA3Server(t)
	issuer := regUser(t, st, nil)
	listed := regUser(t, st, nil)
	windowed := oa3Xonly(t)
	seller := oa3Xonly(t)
	lockedSeller := oa3Xonly(t)
	outsider := oa3Xonly(t)
	setHeight(t, st, 500)
	asset := oa3Asset(t, issuer.AID, store.Rules{})
	asset.Enforcement = "damp"
	asset.Damp = &store.DampBinding{Whitelist: []damp.PredicateEntry{
		{Key: listed.Pubkeys[0]},
		{Key: strings.ToUpper(windowed), RecvAfter: 800},
		{Key: seller},
		{Key: lockedSeller, SendAfter: 900},
	}}
	putAsset(t, st, asset)
	if err := st.Update(func(x *store.State) error {
		x.Snapshots = map[string][]*store.StoredSnapshot{asset.ID: {{Seq: 0, Canonical: json.RawMessage(`{"predicates":{"limit":1000}}`)}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	mustEligible(t, s, map[string]string{"asset": asset.ID, "key": listed.Pubkeys[0]})
	// A registered account answers by its key.
	mustEligible(t, s, map[string]string{"asset": asset.ID, "aid": listed.AID})
	mustRefuse(t, s, map[string]string{"asset": asset.ID, "key": outsider}, "not_whitelisted")
	mustRefuse(t, s, map[string]string{"asset": asset.ID, "key": windowed}, "receive_window")
	setHeight(t, st, 800)
	mustEligible(t, s, map[string]string{"asset": asset.ID, "key": windowed})
	mustRefuse(t, s, map[string]string{"asset": asset.ID, "key": windowed, "atoms": "1001"}, "limit")
	mustEligible(t, s, map[string]string{"asset": asset.ID, "key": windowed, "atoms": "1000", "from": seller})
	mustRefuse(t, s, map[string]string{"asset": asset.ID, "key": windowed, "from": outsider}, "sender_not_whitelisted")
	mustRefuse(t, s, map[string]string{"asset": asset.ID, "key": windowed, "from": lockedSeller}, "sender_locked")
	// A holder's own change: no limit applies.
	mustEligible(t, s, map[string]string{"asset": asset.ID, "key": seller, "atoms": "5000", "from": seller})
}

func TestEligibility_BadRequests(t *testing.T) {
	s, st, _ := newOA3Server(t)
	issuer := regUser(t, st, nil)
	buyer := regUser(t, st, nil)
	asset := oa3Asset(t, issuer.AID, store.Rules{})
	putAsset(t, st, asset)
	for _, c := range []struct {
		params map[string]string
		want   int
	}{
		{map[string]string{"aid": buyer.AID}, 400},
		{map[string]string{"asset": asset.ID}, 400},
		{map[string]string{"asset": strings.Repeat("99", 32), "aid": buyer.AID}, 404},
		{map[string]string{"asset": asset.ID, "aid": buyer.AID, "atoms": "0"}, 400},
		{map[string]string{"asset": asset.ID, "aid": buyer.AID, "atoms": "-3"}, 400},
		{map[string]string{"asset": asset.ID, "key": "zz"}, 400},
		{map[string]string{"asset": asset.ID, "aid": buyer.AID, "from": strings.Repeat("cd", 20)}, 404},
	} {
		if code, _, body := getEligibility(t, s, c.params); code != c.want {
			t.Fatalf("%v: want %d, got %d %s", c.params, c.want, code, body)
		}
	}
	// A network-enforced asset with no published policy cannot be answered.
	d := oa3Asset(t, issuer.AID, store.Rules{})
	d.ID = strings.Repeat("21", 32)
	d.Enforcement = "damp"
	d.Damp = &store.DampBinding{}
	putAsset(t, st, d)
	if code, _, body := getEligibility(t, s, map[string]string{"asset": d.ID, "key": buyer.Pubkeys[0]}); code != 409 {
		t.Fatalf("want 409 with no policy, got %d %s", code, body)
	}
}

// Both endpoints are mounted: the check is public, the onboarding page is the
// issuer's to set.
func TestEligibility_Routes(t *testing.T) {
	s, st, _ := newOA3Server(t)
	s.cfg.IssuerToken = "issuer-test-token"
	issuer := regUser(t, st, nil)
	buyer := regUser(t, st, nil)
	asset := oa3Asset(t, issuer.AID, store.Rules{})
	putAsset(t, st, asset)
	h := s.Routes()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/eligibility?asset="+asset.ID+"&aid="+buyer.AID, nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"eligible":true`) {
		t.Fatalf("GET /v1/eligibility: %d %s", rec.Code, rec.Body.String())
	}
	body := `{"asset":"` + asset.ID + `","name":"Issuer","url":"https://issuer.example/apply"}`
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/issuer/onboarding", bytes.NewBufferString(body)))
	if rec.Code != 401 {
		t.Fatalf("onboarding without the issuer token: want 401, got %d", rec.Code)
	}
	req := httptest.NewRequest("POST", "/v1/issuer/onboarding", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer issuer-test-token")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("onboarding with the token: %d %s", rec.Code, rec.Body.String())
	}
}
