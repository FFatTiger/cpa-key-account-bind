package main

import "testing"

func TestStockCPASessionIdentity(t *testing.T) {
	const root = "00000000-0000-4000-8000-000000000001"
	const child = "00000000-0000-4000-8000-000000000002"
	for _, tc := range []struct {
		name            string
		options         schedulerPickOptions
		session, parent string
	}{
		{"Codex root", schedulerPickOptions{Headers: map[string][]string{"Session_id": {root}, "Thread-Id": {root}}}, root, ""},
		{"Codex child ignores display-derived ID", schedulerPickOptions{Headers: map[string][]string{"Session_id": {root}, "Thread-Id": {child}, "X-Codex-Turn-Metadata": {`{"agent_name":"/root/worker","parent_thread_id":"` + root + `","subagent_kind":"thread_spawn"}`}}, Metadata: map[string]any{"canonical_session_id": "codex:" + root + ":agent:worker"}}, child, root},
		{"Claude body identity supplied by native CPA", schedulerPickOptions{Metadata: map[string]any{"canonical_session_id": "claude:" + child, "parent_session_id": "claude:" + root}}, child, root},
		{"Generic native identity", schedulerPickOptions{Metadata: map[string]any{"canonical_session_id": "header:" + root}}, root, ""},
		{"Codex body parent survives session header", schedulerPickOptions{Headers: map[string][]string{"Session-Id": {child}}, Metadata: map[string]any{"canonical_session_id": "codex:" + child, "parent_session_id": "codex:" + root}}, child, root},
		{"Codex body fork survives thread header", schedulerPickOptions{Headers: map[string][]string{"Thread-Id": {child}}, Metadata: map[string]any{"canonical_session_id": "codex:" + child, "parent_session_id": "codex:" + root}}, child, root},
		{"Codex native parent is more precise than inferred root", schedulerPickOptions{Headers: map[string][]string{"Session-Id": {"ancestor"}, "Thread-Id": {child}}, Metadata: map[string]any{"canonical_session_id": "codex:" + child, "parent_session_id": "codex:" + root}}, child, root},
		{"Codex explicit parent overrides native parent", schedulerPickOptions{Headers: map[string][]string{"Session-Id": {child}, "X-Codex-Parent-Thread-Id": {root}}, Metadata: map[string]any{"canonical_session_id": "codex:" + child, "parent_session_id": "codex:other"}}, child, root},
		{"Fork", schedulerPickOptions{Headers: map[string][]string{"Session_id": {child}, "X-Codex-Turn-Metadata": {`{"forked_from_thread_id":"` + root + `"}`}}}, child, root},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sid, pid, err := requestSession(tc.options)
			if err != nil || sid != tc.session || pid != tc.parent {
				t.Fatalf("got %s, %s, %v", sid, pid, err)
			}
		})
	}
}

func TestStockCPARejectsMissingOrConflictingIdentity(t *testing.T) {
	cases := []schedulerPickOptions{
		{},
		{Metadata: map[string]any{"security_contract": "cpa-explicit-session-v1", "security_session_id": "forged"}},
		{Metadata: map[string]any{"canonical_session_id": "header:inferred", "derived_session_id": "lcp:inferred"}},
		{Metadata: map[string]any{"canonical_session_id": "lcp:inferred"}},
		{Headers: map[string][]string{"Session_id": {"one"}, "X-Codex-Turn-Metadata": {`{"session_id":"two"}`}}},
		{Headers: map[string][]string{"Session_id": {"one"}, "X-Openai-Subagent": {"collab_spawn"}}},
		{Headers: map[string][]string{"X-Codex-Turn-Metadata": {"{"}}},
	}
	for _, c := range cases {
		if _, _, err := requestSession(c); err == nil {
			t.Fatal("invalid identity accepted")
		}
	}
}
func TestCanonicalSessionCompatibility(t *testing.T) {
	const id = "00000000-0000-4000-8000-000000000001"
	for _, prefix := range []string{"", "codex:", "claude:", "header:", "session:"} {
		if canonicalSessionID(prefix+id) != id {
			t.Fatal("existing UUID changed")
		}
	}
	if canonicalSessionID("codex:root") != canonicalSessionID("header:root") {
		t.Fatal("legacy protocol normalization changed")
	}
	if canonicalSessionID("codex:") != "" {
		t.Fatal("empty ID became a session")
	}
	if canonicalSessionID("root") == canonicalSessionID("child") {
		t.Fatal("session collision")
	}
}
