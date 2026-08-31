package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func mustConfigure(t *testing.T, yaml string) {
	t.Helper()
	out := handleConfigure([]byte(`{"config_yaml": "` + base64.StdEncoding.EncodeToString([]byte(yaml)) + `"}`))
	var env envelope
	if err := json.Unmarshal(out, &env); err != nil || !env.OK || env.Error != nil {
		t.Fatalf("configure failed: %s err=%v env=%+v", out, err, env)
	}
}

func pickResult(t *testing.T, req schedulerPickRequest) (schedulerPickResponse, *envelopeError) {
	t.Helper()
	raw, _ := json.Marshal(req)
	out := handlePick(raw)
	var env envelope
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("bad envelope: %s", out)
	}
	if env.Error != nil {
		return schedulerPickResponse{}, env.Error
	}
	var resp schedulerPickResponse
	if err := json.Unmarshal(env.Result, &resp); err != nil {
		t.Fatalf("bad result: %s", env.Result)
	}
	return resp, nil
}

func TestUnconfiguredDefersToHost(t *testing.T) {
	state.Store(nil) // simulate pre-register
	resp, err := pickResult(t, schedulerPickRequest{
		Options:    schedulerPickOptions{Headers: map[string][]string{"Authorization": {"Bearer sk-a"}}},
		Candidates: []schedulerAuthCandidate{{ID: "x.json"}},
	})
	if err != nil || resp.Handled {
		t.Fatalf("want unhandled, got %+v err=%+v", resp, err)
	}
}

func TestPickDecisionTable(t *testing.T) {
	mustConfigure(t, `
bindings:
  - key: "sk-A"
    allow: ["team-*.json", "vip-*"]
  - key: "sk-b"
    allow: ["codex-b*"]
unbound: passthrough
`)
	cands := []schedulerAuthCandidate{
		{ID: "team-1.json", Priority: 5},
		{ID: "team-2.json", Priority: 9},
		{ID: "personal-1.json", Priority: 99},
		{ID: "team-3.json", Priority: 9, Status: "quota_exhausted"},
		{ID: "vip-7", Priority: 2},
	}
	hdrs := func(key string) map[string][]string {
		return map[string][]string{"Authorization": {"Bearer " + key}}
	}

	t.Run("bound key picks highest priority allowed", func(t *testing.T) {
		resp, err := pickResult(t, schedulerPickRequest{Options: schedulerPickOptions{Headers: hdrs("sk-A")}, Candidates: cands})
		if err != nil || !resp.Handled || resp.AuthID != "team-2.json" {
			t.Fatalf("want team-2.json, got %+v err=%+v", resp, err)
		}
	})

	t.Run("key match is case-insensitive", func(t *testing.T) {
		resp, err := pickResult(t, schedulerPickRequest{Options: schedulerPickOptions{Headers: hdrs("SK-a")}, Candidates: cands})
		if err != nil || !resp.Handled || resp.AuthID != "team-2.json" {
			t.Fatalf("case-insensitive key failed: %+v err=%+v", resp, err)
		}
	})

	t.Run("no header key defers to host", func(t *testing.T) {
		resp, err := pickResult(t, schedulerPickRequest{Options: schedulerPickOptions{}, Candidates: cands})
		if err != nil || resp.Handled {
			t.Fatalf("want defer, got %+v err=%+v", resp, err)
		}
	})

	t.Run("unbound key passthrough", func(t *testing.T) {
		resp, err := pickResult(t, schedulerPickRequest{Options: schedulerPickOptions{Headers: hdrs("admin-native-key")}, Candidates: cands})
		if err != nil || resp.Handled {
			t.Fatalf("want defer for unbound, got %+v err=%+v", resp, err)
		}
	})

	t.Run("no allowed candidate hard-fails (isolation)", func(t *testing.T) {
		_, err := pickResult(t, schedulerPickRequest{Options: schedulerPickOptions{Headers: hdrs("sk-b")}, Candidates: cands})
		if err == nil || err.Code != "auth_not_bound" {
			t.Fatalf("want auth_not_bound, got %+v", err)
		}
	})

	t.Run("empty candidate list hard-fails for bound key", func(t *testing.T) {
		_, err := pickResult(t, schedulerPickRequest{Options: schedulerPickOptions{Headers: hdrs("sk-A")}})
		if err == nil || err.Code != "auth_not_bound" {
			t.Fatalf("want auth_not_bound, got %+v", err)
		}
	})

	t.Run("unusable statuses filtered but still isolated", func(t *testing.T) {
		onlySick := []schedulerAuthCandidate{{ID: "team-3.json", Status: "quota_exhausted"}, {ID: "personal-1.json"}}
		_, err := pickResult(t, schedulerPickRequest{Options: schedulerPickOptions{Headers: hdrs("sk-A")}, Candidates: onlySick})
		if err == nil || err.Code != "auth_not_bound" {
			t.Fatalf("want auth_not_bound, got %+v", err)
		}
	})
}

func TestUnboundDeny(t *testing.T) {
	mustConfigure(t, `
bindings:
  - key: "sk-a"
    allow: ["x*"]
unbound: deny
`)
	resp, err := pickResult(t, schedulerPickRequest{
		Options:    schedulerPickOptions{Headers: map[string][]string{"X-Api-Key": {"sk-someone-else"}}},
		Candidates: []schedulerAuthCandidate{{ID: "x-1"}},
	})
	if err == nil || err.Code != "key_not_bound" {
		t.Fatalf("want key_not_bound, got %+v resp=%+v", err, resp)
	}
	// bound key still works
	resp, err = pickResult(t, schedulerPickRequest{
		Options:    schedulerPickOptions{Headers: map[string][]string{"X-Api-Key": {"sk-a"}}},
		Candidates: []schedulerAuthCandidate{{ID: "x-1"}},
	})
	if err != nil || !resp.Handled || resp.AuthID != "x-1" {
		t.Fatalf("bound key under deny policy failed: %+v err=%+v", resp, err)
	}
}

func TestHeaderSpellings(t *testing.T) {
	mustConfigure(t, `
bindings:
  - key: "k1"
    allow: ["a*"]
  - key: "k2"
    allow: ["b*"]
  - key: "k3"
    allow: ["c*"]
`)
	cases := []struct {
		name    string
		headers map[string][]string
		wantID  string
	}{
		{"bearer", map[string][]string{"Authorization": {"Bearer k1"}}, "a-1"},
		{"x-api-key", map[string][]string{"X-Api-Key": {"k2"}}, "b-1"},
		{"x-goog lower", map[string][]string{"x-goog-api-key": {"k3"}}, "c-1"},
		{"weird case", map[string][]string{"aUtHoRiZaTiOn": {"bearer k1"}}, "a-1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := pickResult(t, schedulerPickRequest{
				Options:    schedulerPickOptions{Headers: tc.headers},
				Candidates: []schedulerAuthCandidate{{ID: "a-1"}, {ID: "b-1"}, {ID: "c-1"}},
			})
			if err != nil || !resp.Handled || resp.AuthID != tc.wantID {
				t.Fatalf("want %s, got %+v err=%+v", tc.wantID, resp, err)
			}
		})
	}
}

func TestConfigValidation(t *testing.T) {
	bad := []string{
		"bindings:\n  - allow: [\"x\"]",                                             // missing key
		"bindings:\n  - key: k",                                                     // no allow patterns
		"bindings:\n  - key: k\n    allow: [\"[\"]",                                 // invalid glob
		"bindings:\n  - key: k\n    allow: [\"x\"]\n  - key: k\n    allow: [\"y\"]", // dup
		"unbound: sometimes",
	}
	for i, cfg := range bad {
		out := handleConfigure([]byte(`{"config_yaml": "` + base64.StdEncoding.EncodeToString([]byte(cfg)) + `"}`))
		var env envelope
		_ = json.Unmarshal(out, &env)
		if env.OK || env.Error == nil || env.Error.Code != "invalid_config" {
			t.Fatalf("case %d: want invalid_config, got %s", i, out)
		}
	}
}

func TestReconfigureSwapsPolicy(t *testing.T) {
	mustConfigure(t, "bindings:\n  - key: k\n    allow: [\"old*\"]")
	resp, err := pickResult(t, schedulerPickRequest{
		Options:    schedulerPickOptions{Headers: map[string][]string{"Authorization": {"Bearer k"}}},
		Candidates: []schedulerAuthCandidate{{ID: "old-1"}, {ID: "new-1"}},
	})
	if err != nil || resp.AuthID != "old-1" {
		t.Fatalf("phase1: %+v err=%+v", resp, err)
	}
	mustConfigure(t, "bindings:\n  - key: k\n    allow: [\"new*\"]")
	resp, err = pickResult(t, schedulerPickRequest{
		Options:    schedulerPickOptions{Headers: map[string][]string{"Authorization": {"Bearer k"}}},
		Candidates: []schedulerAuthCandidate{{ID: "old-1"}, {ID: "new-1"}},
	})
	if err != nil || resp.AuthID != "new-1" {
		t.Fatalf("phase2: %+v err=%+v", resp, err)
	}
}

func TestPanicRecovery(t *testing.T) {
	out := safeCall("scheduler.pick", []byte("{not-json"))
	var env envelope
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("expected envelope, got %s", out)
	}
	// malformed payload must yield a clean error envelope, not a crash
	if env.OK {
		t.Fatalf("want error envelope, got %s", out)
	}
	if !strings.Contains(string(out), "code") {
		t.Fatalf("want coded error, got %s", out)
	}
}

func TestCompactStringBindings(t *testing.T) {
	mustConfigure(t, `
bindings:
  - "sk-a=team-*.json,vip-*"
  - key: "sk-b"
    allow: ["codex-b*"]
unbound: passthrough
`)
	hdrs := func(k string) map[string][]string { return map[string][]string{"Authorization": {"Bearer " + k}} }
	cands := []schedulerAuthCandidate{
		{ID: "team-1.json"}, {ID: "vip-2"}, {ID: "codex-b-3"}, {ID: "other-4"},
	}
	resp, err := pickResult(t, schedulerPickRequest{Options: schedulerPickOptions{Headers: hdrs("sk-a")}, Candidates: cands})
	if err != nil || !resp.Handled || resp.AuthID != "team-1.json" {
		t.Fatalf("compact binding a: %+v err=%+v", resp, err)
	}
	resp, err = pickResult(t, schedulerPickRequest{Options: schedulerPickOptions{Headers: hdrs("sk-b")}, Candidates: cands})
	if err != nil || !resp.Handled || resp.AuthID != "codex-b-3" {
		t.Fatalf("object binding b: %+v err=%+v", resp, err)
	}
	_, err = pickResult(t, schedulerPickRequest{Options: schedulerPickOptions{Headers: hdrs("sk-a")}, Candidates: []schedulerAuthCandidate{{ID: "codex-b-3"}}})
	if err == nil || err.Code != "auth_not_bound" {
		t.Fatalf("want auth_not_bound for bound key with no matching candidate, got %+v", err)
	}
}

func TestCompactBindingValidation(t *testing.T) {
	for _, bad := range []string{
		"bindings:\n  - \"no-equals-sign\"",
		"bindings:\n  - \"=onlyglobs\"",
		"bindings:\n  - 42",
	} {
		out := handleConfigure([]byte(`{"config_yaml": "` + base64.StdEncoding.EncodeToString([]byte(bad)) + `"}`))
		var env envelope
		_ = json.Unmarshal(out, &env)
		if env.OK || env.Error == nil {
			t.Fatalf("want error for %q, got %s", bad, out)
		}
	}
}

func TestUnknownMethod(t *testing.T) {
	out := dispatch("bogus.method", nil)
	var env envelope
	_ = json.Unmarshal(out, &env)
	if env.OK || env.Error == nil || env.Error.Code != "unknown_method" {
		t.Fatalf("want unknown_method, got %s", out)
	}
}
