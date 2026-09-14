package main

import "testing"

// CPA supplies candidates after checking model-specific cooldowns and hard
// authentication failures. A historical aggregate error is not a revocation.
func TestBoundCredentialRetriesAfterHostMakesItAvailable(t *testing.T) {
	mustConfigure(t, "bindings:\n  - key: work-key\n    allow: [work-credential]\nunbound: deny\n")
	req := schedulerPickRequest{
		Options: schedulerPickOptions{Headers: map[string][]string{"Authorization": {"Bearer work-key"}}},
		Candidates: []schedulerAuthCandidate{
			{ID: "personal-credential", Status: "active", Priority: 100},
			{ID: "work-credential", Status: "error"},
		},
	}
	got, err := pickResult(t, req)
	if err != nil || !got.Handled || got.AuthID != "work-credential" {
		t.Fatalf("eligible retry rejected: result=%+v error=%+v", got, err)
	}
	// A host-blocked credential is absent, so the plugin must not fall back
	// to a different account while waiting for the host to allow a retry.
	req.Candidates = req.Candidates[:1]
	if _, err := pickResult(t, req); err == nil {
		t.Fatal("missing bound credential fell back to a different account")
	}
}

func TestIsolationRetriesOnlyWithinAuthorizedScope(t *testing.T) {
	p := isolationFixture(t)
	req := isolationRequest("work-retry", "", "work/litellm/model")
	for i := range req.Candidates {
		req.Candidates[i].Status = "error"
	}
	b := &binding{patterns: []string{"l"}}
	got, err := p.filter(req, b)
	if err != nil || len(got) != 1 || got[0].ID != "l" {
		t.Fatalf("eligible scoped retry rejected: result=%+v error=%v", got, err)
	}
	req.Model = "personal/codex-oauth/model"
	if _, err := p.filter(req, b); err == nil {
		t.Fatal("retry escaped downstream key's work scope")
	}
	if _, err := p.filter(req, nil); err == nil {
		t.Fatal("retry changed the persisted task scope")
	}
	// A genuinely disabled candidate must remain rejected.
	req.Model = "work/litellm/model"
	req.Candidates[2].Status = "disabled"
	if _, err := p.filter(req, b); err == nil {
		t.Fatal("disabled credential was accepted")
	}
}
