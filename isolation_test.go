package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func isolationFixture(t *testing.T) *isolationPolicy {
	t.Helper()
	p, err := compileIsolation(isolationConfig{Enabled: true, StateFile: filepath.Join(t.TempDir(), "state.json"), Credentials: []credentialClass{
		{ID: "p", Provider: "codex", Scope: "personal", Source: "codex-oauth"},
		{ID: "w", Provider: "claude", Scope: "work", Source: "claude-oauth"},
		{ID: "l", Provider: "codex", Scope: "work", Source: "litellm"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	p.requireScopeBoundKey = false
	if err = p.writeState(sessionFile{Version: 1, Sessions: map[string]sessionBinding{}}); err != nil {
		t.Fatal(err)
	}
	return p
}
func isolationRequest(id, parent, route string) schedulerPickRequest {
	return schedulerPickRequest{Model: route, Options: schedulerPickOptions{Headers: map[string][]string{"Authorization": {"Bearer test-key"}}, Metadata: map[string]any{"canonical_session_id": id, "parent_session_id": parent}}, Candidates: []schedulerAuthCandidate{{ID: "p", Provider: "codex"}, {ID: "w", Provider: "claude"}, {ID: "l", Provider: "codex"}, {ID: "unknown", Provider: "codex"}}}
}
func TestIsolationTrees(t *testing.T) {
	p := isolationFixture(t)
	cases := []struct{ id, parent, route, want string }{
		{"personal-root", "", "personal/codex-oauth/model", "p"},
		{"personal-root", "", "work/claude-oauth/model", ""},
		{"personal-root", "", "work/litellm/model", ""},
		{"work-root", "", "work/claude-oauth/model", "w"},
		{"work-root", "", "work/litellm/model", "l"},
		{"work-root", "", "personal/codex-oauth/model", ""},
		{"child", "work-root", "work/litellm/model", "l"},
		{"grandchild", "child", "work/claude-oauth/other-model", "w"},
		{"grandchild", "child", "personal/codex-oauth/model", ""},
		{"child", "personal-root", "personal/codex-oauth/model", ""},
		{"orphan", "unknown-parent", "personal/codex-oauth/model", ""},
		{"personal-child", "personal-root", "personal/codex-oauth/model", "p"},
		{"personal-grandchild", "personal-child", "work/litellm/model", ""},
	}
	for _, c := range cases {
		t.Run(c.id+"/"+c.route, func(t *testing.T) {
			got, err := p.filter(isolationRequest(c.id, c.parent, c.route), nil)
			if c.want == "" {
				if err == nil {
					t.Fatal("forbidden route allowed")
				}
				return
			}
			if err != nil || len(got) != 1 || got[0].ID != c.want {
				t.Fatalf("selection=%v error=%v", got, err)
			}
		})
	}
	// New policy object represents a plugin restart: same persisted tree remains bound.
	q := *p
	if _, err := q.filter(isolationRequest("work-root", "", "personal/codex-oauth/model"), nil); err == nil {
		t.Fatal("restart changed scope")
	}
	if _, err := q.filter(isolationRequest("grandchild", "child", "work/litellm/model"), nil); err != nil {
		t.Fatal(err)
	}
}
func TestIsolationFailures(t *testing.T) {
	for _, name := range []string{"missing-state", "corrupt-state", "trailing-state", "missing-session", "missing-parent", "bare-model", "spoof-source", "spoof-provider", "binding", "quota", "retry", "capacity"} {
		t.Run(name, func(t *testing.T) {
			p := isolationFixture(t)
			r := isolationRequest("root", "", "personal/codex-oauth/model")
			var b *binding
			switch name {
			case "missing-state":
				os.Remove(p.file)
			case "corrupt-state":
				os.WriteFile(p.file, []byte(`{"version":1}`), 0600)
			case "trailing-state":
				f, _ := os.OpenFile(p.file, os.O_APPEND|os.O_WRONLY, 0600)
				f.WriteString(`{}`)
				f.Close()
			case "missing-session":
				delete(r.Options.Metadata, "canonical_session_id")
			case "missing-parent":
				r.Options.Metadata["canonical_session_id"] = "claude:root:agent:orphan"
			case "bare-model":
				r.Model = "model"
			case "spoof-source":
				r.Model = "personal/litellm/model"
			case "spoof-provider":
				r.Candidates[0].Provider = "claude"
			case "binding":
				b = &binding{patterns: []string{"w"}}
			case "quota":
				r.Candidates[0].Status = "quota_exhausted"
			case "retry":
				r.Candidates = r.Candidates[1:]
			case "capacity":
				p.limit = 1
				p.filter(isolationRequest("existing", "", "personal/codex-oauth/model"), nil)
			}
			if _, err := p.filter(r, b); err == nil {
				t.Fatal("failed open")
			}
		})
	}
}
func TestIsolationConcurrentScopeImmutability(t *testing.T) {
	p := isolationFixture(t)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			route := "personal/codex-oauth/model"
			if i%2 == 0 {
				route = "work/litellm/model"
			}
			p.filter(isolationRequest("shared-root", "", route), nil)
		}(i)
	}
	wg.Wait()
	s, err := p.readState()
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Sessions) != 1 {
		t.Fatal("lost/duplicated session")
	}
	chosen := s.Sessions[sessionHash(canonicalSessionID("shared-root"))].Scope
	other := "work/litellm/model"
	if chosen == "work" {
		other = "personal/codex-oauth/model"
	}
	if _, err = p.filter(isolationRequest("shared-root", "", other), nil); err == nil {
		t.Fatal("cross-scope race")
	}
}
func TestIsolationSchedulerComposition(t *testing.T) {
	old := state.Load()
	defer state.Store(old)
	p := defaultPolicy()
	p.isolation = isolationFixture(t)
	state.Store(p)
	r := isolationRequest("root", "", "personal/codex-oauth/model")
	raw, _ := json.Marshal(r)
	var e envelope
	json.Unmarshal(handlePick(raw), &e)
	var result schedulerPickResponse
	json.Unmarshal(e.Result, &result)
	if !e.OK || !result.Handled || result.AuthID != "p" {
		t.Fatal(string(handlePick(raw)))
	}
	p.byKey["test-key"] = &binding{patterns: []string{"w"}}
	json.Unmarshal(handlePick(raw), &e)
	if e.OK {
		t.Fatal("binding broadened")
	}
	delete(p.byKey, "test-key")
	p.unboundPassthrough = false
	json.Unmarshal(handlePick(raw), &e)
	if e.OK {
		t.Fatal("unbound deny ignored")
	}
	r.Options.Headers = nil
	raw, _ = json.Marshal(r)
	json.Unmarshal(handlePick(raw), &e)
	if e.OK {
		t.Fatal("missing key allowed")
	}
}

func TestIsolationStateIntegrityAndLock(t *testing.T) {
	for _, test := range []string{"checksum", "lock"} {
		t.Run(test, func(t *testing.T) {
			p := isolationFixture(t)
			if test == "checksum" {
				data, _ := os.ReadFile(p.file)
				var s sessionFile
				json.Unmarshal(data, &s)
				s.Checksum = "bad"
				data, _ = json.Marshal(s)
				os.WriteFile(p.file, data, 0600)
			} else {
				os.WriteFile(p.file+".lock", nil, 0600)
			}
			if _, err := p.filter(isolationRequest("root", "", "personal/codex-oauth/model"), nil); err == nil {
				t.Fatal("invalid state authorized")
			}
		})
	}
}
func TestIsolationDuplicateModelProvenance(t *testing.T) {
	p := isolationFixture(t)
	for _, c := range []struct{ route, id string }{{"personal/codex-oauth/shared", "p"}, {"work/litellm/shared", "l"}, {"work/claude-oauth/shared", "w"}} {
		a, err := p.filter(isolationRequest(c.id, "", c.route), nil)
		if err != nil || len(a) != 1 || a[0].ID != c.id {
			t.Fatal("duplicate route collapsed")
		}
	}
}

func TestScopeBoundKeyCannotSpoofNewRoot(t *testing.T) {
	p := isolationFixture(t)
	p.requireScopeBoundKey = true
	b := &binding{patterns: []string{"p"}}
	if _, err := p.filter(isolationRequest("personal", "", "personal/codex-oauth/model"), b); err != nil {
		t.Fatal(err)
	}
	if _, err := p.filter(isolationRequest("forged-new-root", "", "work/litellm/model"), b); err == nil {
		t.Fatal("hidden ancestry bypassed scope-bound key")
	}
	if _, err := p.filter(isolationRequest("unbound", "", "personal/codex-oauth/model"), nil); err == nil {
		t.Fatal("unbound key allowed")
	}
	if _, err := p.filter(isolationRequest("ambiguous", "", "personal/codex-oauth/model"), &binding{patterns: []string{"*"}}); err == nil {
		t.Fatal("multi-scope key allowed")
	}
	w := &binding{patterns: []string{"w", "l"}}
	if _, err := p.filter(isolationRequest("work", "", "work/litellm/model"), w); err != nil {
		t.Fatal(err)
	}
}

func TestIsolationNativeBodyParentWithCodexHeaders(t *testing.T) {
	p := isolationFixture(t)
	if _, err := p.filter(isolationRequest("work-root", "", "work/litellm/model"), nil); err != nil {
		t.Fatal(err)
	}
	r := isolationRequest("codex:child", "codex:work-root", "personal/codex-oauth/model")
	r.Options.Headers["Session-Id"] = []string{"child"}
	if _, err := p.filter(r, nil); err == nil {
		t.Fatal("work descendant admitted as personal root")
	}
	r.Model = "work/litellm/model"
	if _, err := p.filter(r, nil); err != nil {
		t.Fatal(err)
	}
	r.Options.Headers["X-Codex-Parent-Thread-Id"] = []string{"work-root"}
	if _, err := p.filter(r, nil); err != nil {
		t.Fatalf("resume with explicit ancestry: %v", err)
	}
}

func TestIsolationScopeAndStateSizeLimits(t *testing.T) {
	scope := strings.Repeat("a", maxScopeLength)
	cfg := isolationConfig{Enabled: true, StateFile: filepath.Join(t.TempDir(), "state.json"), MaxSessions: 100, Credentials: []credentialClass{{ID: "p", Provider: "codex", Scope: scope, Source: "codex-oauth"}}}
	for _, size := range []int{maxScopeLength + 1, 300} {
		cfg.Credentials[0].Scope = strings.Repeat("a", size)
		if _, err := compileIsolation(cfg); err == nil {
			t.Fatalf("accepted %d-byte scope", size)
		}
	}
	cfg.Credentials[0].Scope = scope
	p, err := compileIsolation(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p.requireScopeBoundKey = false
	if err := p.writeState(sessionFile{Version: 1, Sessions: map[string]sessionBinding{}}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < p.limit; i++ {
		parent := ""
		if i > 0 {
			parent = "root-0"
		}
		if _, err := p.filter(isolationRequest(fmt.Sprintf("root-%d", i), parent, scope+"/codex-oauth/model"), nil); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	for i := 0; i < p.limit; i++ {
		parent := ""
		if i > 0 {
			parent = "root-0"
		}
		if _, err := p.filter(isolationRequest(fmt.Sprintf("root-%d", i), parent, scope+"/codex-oauth/model"), nil); err != nil {
			t.Fatalf("resume %d: %v", i, err)
		}
	}
	if _, err := p.filter(isolationRequest("over-capacity", "", scope+"/codex-oauth/model"), nil); err == nil {
		t.Fatal("capacity exceeded")
	}
	before, err := os.ReadFile(p.file)
	if err != nil {
		t.Fatal(err)
	}
	oversized := sessionFile{Version: 1, Sessions: map[string]sessionBinding{sessionHash("root"): {Scope: strings.Repeat("a", int(p.maxStateBytes()))}}}
	if err := p.writeState(oversized); err == nil {
		t.Fatal("oversized replacement accepted")
	}
	after, err := os.ReadFile(p.file)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("oversized replacement changed state")
	}
	if _, err := p.readState(); err != nil {
		t.Fatal(err)
	}
}
