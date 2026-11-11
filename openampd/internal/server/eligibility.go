package server

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/ConcatenaLabs/openamp/openampd/internal/damp"
	"github.com/ConcatenaLabs/openamp/openampd/internal/store"
)

// eligibility is GET /v1/eligibility's answer: may this party receive the asset
// now, and if not, why, and where to go to be approved.
type eligibility struct {
	Asset       string `json:"asset"`
	Enforcement string `json:"enforcement"` // "cosign" or "damp"
	AID         string `json:"aid,omitempty"`
	Key         string `json:"key,omitempty"`
	Atoms       uint64 `json:"atoms"`
	Height      int64  `json:"height"`
	Eligible    bool   `json:"eligible"`
	// Code is a stable word for the rule that refused, for a wallet to choose
	// its words by; Reason is the sentence, as the policy engine says it.
	Code       string            `json:"code,omitempty"`
	Reason     string            `json:"reason,omitempty"`
	Onboarding *store.Onboarding `json:"onboarding,omitempty"`
	// OperatorOnboarding is this server's operator's page, given beside the
	// asset's own so a wallet can try the asset's registry entry in between.
	OperatorOnboarding *store.Onboarding `json:"operator_onboarding,omitempty"`
}

// handleEligibility answers, before any money moves, whether a party may receive
// an asset now: GET /v1/eligibility?asset=<id>&(aid=<aid>|key=<x-only>)
// [&atoms=<n>][&from=<aid or key>].
//
// For a co-signed asset it runs checkRules, the code every transfer's approval
// runs, over a receipt of `atoms` (default 1) by the party, so the answer cannot
// drift from what a co-sign will decide. Without `from` the sender is nobody in
// particular: rules that bind every secondary sale (the lock-in, a category
// window) still apply, and rules that depend on one sender's history (velocity,
// vesting, pledges) do not; with `from` they do, for that sender. Holder caps
// read the chain, as a co-sign does. For a network-enforced asset it reads the
// current policy's whitelist: the party's key must be listed, its receive window
// open, and `atoms` within the transfer limit.
//
// A refusal is an answer, not an error: 200 with eligible:false, a code, the
// reason and, where the issuer has said or the contract names a domain, where
// to ask for approval. Nothing is signed or recorded, so a quote may call it
// freely.
func (s *Server) handleEligibility(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	assetID := q.Get("asset")
	if assetID == "" {
		httpErr(w, 400, "asset is required")
		return
	}
	if q.Get("aid") == "" && q.Get("key") == "" {
		httpErr(w, 400, "aid or key is required")
		return
	}
	atoms := uint64(1)
	if v := q.Get("atoms"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil || n == 0 {
			httpErr(w, 400, "atoms must be a positive whole number")
			return
		}
		atoms = n
	}
	var asset *store.Asset
	var height int64
	s.st.View(func(st *store.State) {
		height = st.Height
		if a, ok := st.Assets[assetID]; ok {
			cp := *a
			asset = &cp
		}
	})
	if asset == nil {
		httpErr(w, 404, "unknown asset")
		return
	}
	out := &eligibility{Asset: asset.ID, Enforcement: "cosign", Atoms: atoms, Height: height}
	var err error
	if asset.Enforcement == "damp" {
		out.Enforcement = "damp"
		err = s.dampEligibility(out, asset, q.Get("aid"), q.Get("key"), q.Get("from"))
	} else {
		err = s.cosignEligibility(out, asset, q.Get("aid"), q.Get("key"), q.Get("from"))
	}
	if err != nil {
		if e, ok := err.(*httpError); ok {
			httpErr(w, e.status, "%s", e.msg)
			return
		}
		httpErr(w, 503, "eligibility: %v", err)
		return
	}
	if !out.Eligible {
		out.Onboarding = onboardingFor(asset)
		out.OperatorOnboarding = s.cfg.Onboarding
	}
	httpJSON(w, out)
}

// httpError carries a client mistake (400, 404) out of the eligibility helpers;
// any other error is the server's (503).
type httpError struct {
	status int
	msg    string
}

func (e *httpError) Error() string { return e.msg }

func (s *Server) cosignEligibility(out *eligibility, asset *store.Asset, aid, key, from string) error {
	if aid == "" {
		k, err := xonlyParam("key", key)
		if err != nil {
			return err
		}
		aid = store.AID([]string{k})
	}
	out.AID = aid
	var user, sender *store.User
	s.st.View(func(st *store.State) {
		if u, ok := st.Users[aid]; ok {
			cp := *u
			user = &cp
		}
		if from != "" {
			if u, ok := st.Users[from]; ok {
				cp := *u
				sender = &cp
			} else if k, err := xonlyParam("from", from); err == nil {
				if u, ok := st.Users[store.AID([]string{k})]; ok {
					cp := *u
					sender = &cp
				}
			}
		}
	})
	if user == nil {
		out.Code = "unregistered"
		out.Reason = "this account is not registered with the asset's policy server: register its key first (POST /v1/users)"
		return nil
	}
	if from != "" && sender == nil {
		return &httpError{404, "unknown sender (from)"}
	}
	if user.Frozen && user.AID != asset.IssuerAID {
		out.Code = "frozen"
		out.Reason = "this account is frozen by the issuer"
		return nil
	}
	recipients := map[string]uint64{aid: out.Atoms}
	if sender == nil {
		// Nobody in particular: no history, no vesting, no pledge, not a
		// primary sender. An empty AID matches no record and no rule entry.
		sender = &store.User{}
	} else {
		if sender.Frozen {
			out.Code = "sender_frozen"
			out.Reason = "the seller's account is frozen by the issuer"
			return nil
		}
		if sender.AID == aid {
			recipients = map[string]uint64{} // a holder moving its own coins receives nothing
		}
	}
	if err := s.checkRules(asset, sender, recipients, 0, out.Height); err != nil {
		pr, ok := err.(*PolicyRefusal)
		if !ok {
			return err
		}
		out.Code = pr.Code
		if out.Code == "" {
			out.Code = "rules"
		}
		out.Reason = pr.Reason
		return nil
	}
	out.Eligible = true
	return nil
}

func (s *Server) dampEligibility(out *eligibility, asset *store.Asset, aid, key, from string) error {
	if key == "" {
		var u *store.User
		s.st.View(func(st *store.State) {
			if x, ok := st.Users[aid]; ok {
				cp := *x
				u = &cp
			}
		})
		if u == nil || len(u.Pubkeys) == 0 {
			return &httpError{404, "unknown aid: a network-enforced asset names its holders by key, so pass key=<x-only>"}
		}
		key = u.Pubkeys[0]
	}
	k, err := xonlyParam("key", key)
	if err != nil {
		return err
	}
	out.Key = k
	entries := s.dampHolderList(asset)
	if len(entries) == 0 {
		return &httpError{409, "the asset has no published policy to check against"}
	}
	find := func(k string) (damp.PredicateEntry, bool) {
		for _, e := range entries {
			if strings.EqualFold(e.Key, k) {
				return e, true
			}
		}
		return damp.PredicateEntry{}, false
	}
	// A transaction can claim at most the tip's height as its lock time and is
	// mined in the next block, so a window opens once the tip has reached it.
	tip := uint32(0)
	if out.Height > 0 {
		tip = uint32(out.Height)
	}
	e, ok := find(k)
	if !ok {
		out.Code = "not_whitelisted"
		out.Reason = "this key is not on the asset's whitelist"
		return nil
	}
	if e.RecvAfter > tip {
		out.Code = "receive_window"
		out.Reason = "this key may receive the asset from height " + strconv.FormatUint(uint64(e.RecvAfter), 10)
		return nil
	}
	if from != "" {
		fk, err := xonlyParam("from", from)
		if err != nil {
			return err
		}
		se, ok := find(fk)
		if !ok {
			out.Code = "sender_not_whitelisted"
			out.Reason = "the seller's key is not on the asset's whitelist"
			return nil
		}
		if se.SendAfter > tip {
			out.Code = "sender_locked"
			out.Reason = "the seller may send the asset from height " + strconv.FormatUint(uint64(se.SendAfter), 10)
			return nil
		}
		if strings.EqualFold(fk, k) {
			out.Eligible = true // the sender's own change: no limit, no window
			return nil
		}
	}
	if latest, ok := s.st.LatestSnapshot(asset.ID); ok {
		var snap damp.Snapshot
		if err := json.Unmarshal(latest.Canonical, &snap); err == nil && snap.Predicates.Limit != nil && out.Atoms > *snap.Predicates.Limit {
			out.Code = "limit"
			out.Reason = "one transfer of the asset may carry at most " + strconv.FormatUint(*snap.Predicates.Limit, 10) + " atoms"
			return nil
		}
	}
	out.Eligible = true
	return nil
}

func xonlyParam(name, v string) (string, error) {
	b, err := hex.DecodeString(v)
	if err != nil || len(b) != 32 {
		return "", &httpError{400, name + " must be a 64-hex x-only key"}
	}
	return strings.ToLower(v), nil
}

// onboardingFor is where an unapproved party goes: what the issuer set, else
// the domain the issuance contract names, else nothing.
func onboardingFor(asset *store.Asset) *store.Onboarding {
	if asset.Onboarding != nil && asset.Onboarding.URL != "" {
		cp := *asset.Onboarding
		return &cp
	}
	var c struct {
		Entity struct {
			Domain string `json:"domain"`
		} `json:"entity"`
	}
	if len(asset.Contract) > 0 && json.Unmarshal(asset.Contract, &c) == nil && validDomain(c.Entity.Domain) {
		return &store.Onboarding{Name: c.Entity.Domain, URL: "https://" + c.Entity.Domain}
	}
	return nil
}

func validDomain(d string) bool {
	if d == "" || len(d) > 253 || !strings.Contains(d, ".") {
		return false
	}
	for _, r := range d {
		if !(r == '.' || r == '-' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// handleOnboarding sets or clears an asset's onboarding page:
// POST /v1/issuer/onboarding {"asset", "name", "url"}; an empty url clears it.
func (s *Server) handleOnboarding(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Asset string `json:"asset"`
		Name  string `json:"name"`
		URL   string `json:"url"`
	}
	if err := decodeBody(r, &req); err != nil {
		httpErr(w, 400, "%v", err)
		return
	}
	if req.URL != "" {
		u, err := url.Parse(req.URL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || len(req.URL) > 512 {
			httpErr(w, 400, "url must be an http(s) address of at most 512 characters")
			return
		}
	}
	if !utf8.ValidString(req.Name) || utf8.RuneCountInString(req.Name) > 100 {
		httpErr(w, 400, "name must be at most 100 characters")
		return
	}
	err := s.st.Update(func(st *store.State) error {
		a, ok := st.Assets[req.Asset]
		if !ok {
			return &httpError{404, "unknown asset"}
		}
		if req.URL == "" {
			a.Onboarding = nil
		} else {
			a.Onboarding = &store.Onboarding{Name: req.Name, URL: req.URL}
		}
		return nil
	})
	if err != nil {
		if e, ok := err.(*httpError); ok {
			httpErr(w, e.status, "%s", e.msg)
			return
		}
		httpErr(w, 500, "%v", err)
		return
	}
	s.st.AppendLog("onboarding", req)
	httpJSON(w, map[string]any{"asset": req.Asset, "onboarding": req.URL != ""})
}
