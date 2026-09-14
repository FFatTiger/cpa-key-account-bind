package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var canonicalUUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// canonicalSessionID preserves the UUID projection used by the previous
// deployment so existing persisted sessions survive migration to stock CPA.
// Adapted from CPA 7.2.155 sdk/cliproxy/session/identity.go; see THIRD_PARTY_NOTICES.
func canonicalSessionID(id string) string {
	id = strings.TrimSpace(id)
	prefixes := []string{"lcp:v1:", "lcp:", "ctx:v1:", "ctx:", "codex:", "claude:", "header:", "session:", "affinity:", "slot:", "task:", "conv:", "thread:", "clientreq:", "geminicache:", "pck:", "user:", "execution:", "agy:", "derived:"}
	for {
		changed := false
		for _, p := range prefixes {
			if strings.HasPrefix(id, p) {
				id = strings.TrimSpace(strings.TrimPrefix(id, p))
				changed = true
				break
			}
		}
		if !changed {
			break
		}
	}
	if id == "" {
		return ""
	}
	if canonicalUUID.MatchString(id) {
		return strings.ToLower(id)
	}
	if i := strings.Index(id, ":"); i > 0 && canonicalUUID.MatchString(strings.TrimSpace(id[i+1:])) {
		return strings.ToLower(strings.TrimSpace(id[i+1:]))
	}
	sum := sha256.Sum256([]byte("cpa:canonical-uuid:v1\x00" + id))
	u := [16]byte(sum[:16])
	u[6] = (u[6] & 0x0f) | 0x80
	u[8] = (u[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", u[:4], u[4:6], u[6:8], u[8:10], u[10:])
}

// requestSession uses the existing CPA scheduler metadata for clients whose
// identity is in the body (e.g. Claude). Codex headers take precedence so an
// agent display name cannot replace the actual thread ID used by grandchildren.
// It intentionally does not consume any fields from the former custom core.
func requestSession(opts schedulerPickOptions) (string, string, error) {
	get := func(names ...string) string {
		for _, n := range names {
			if v, ok := lookupHeader(opts.Headers, n); ok {
				return v
			}
		}
		return ""
	}
	native, _ := opts.Metadata["canonical_session_id"].(string)
	parent, _ := opts.Metadata["parent_session_id"].(string)
	sid := native
	child := strings.Contains(native, ":agent:")
	root := get("Session-Id", "Session_id")
	thread := get("Thread-Id", "Thread_id")
	var turn struct {
		Session string `json:"session_id"`
		Thread  string `json:"thread_id"`
		Parent  string `json:"parent_thread_id"`
		Fork    string `json:"forked_from_thread_id"`
		ForkID  string `json:"forked_from_id"`
		Kind    string `json:"subagent_kind"`
	}
	if raw := get("X-Codex-Turn-Metadata"); raw != "" {
		if json.Unmarshal([]byte(raw), &turn) != nil {
			return "", "", errors.New("invalid Codex turn metadata")
		}
		if (root != "" && turn.Session != "" && root != turn.Session) || (thread != "" && turn.Thread != "" && thread != turn.Thread) {
			return "", "", errors.New("conflicting Codex session identities")
		}
	}
	if root == "" {
		root = turn.Session
	}
	if thread == "" {
		thread = turn.Thread
	}
	if root != "" || thread != "" {
		sid = thread
		if sid == "" {
			sid = root
		}
		explicitParent := get("X-Codex-Parent-Thread-Id")
		if explicitParent == "" {
			explicitParent = turn.Parent
		}
		if explicitParent == "" {
			explicitParent = turn.Fork
		}
		if explicitParent == "" {
			explicitParent = turn.ForkID
		}
		sub := get("X-Openai-Subagent")
		child = parent != "" || explicitParent != "" || turn.Kind == "thread_spawn" || (sub != "" && sub != "0" && !strings.EqualFold(sub, "false")) || (thread != "" && root != "" && thread != root)
		if explicitParent != "" {
			parent = explicitParent
		} else if parent == "" && child && root != "" && root != sid {
			parent = root
		}
		// Without an explicit parent header, retain CPA body-derived ancestry.
		// Session headers identify a child; they do not declare it a new root.
	} else {
		if derived, _ := opts.Metadata["derived_session_id"].(string); derived != "" {
			return "", "", errors.New("explicit session identity unavailable")
		}
		for _, prefix := range []string{"lcp:", "ctx:", "derived:"} {
			if strings.HasPrefix(sid, prefix) {
				return "", "", errors.New("explicit session identity unavailable")
			}
		}
	}
	sid = canonicalSessionID(sid)
	parent = canonicalSessionID(parent)
	if sid == "" || sid == parent || (child && parent == "") {
		return "", "", errors.New("explicit session or parent identity unavailable")
	}
	return sid, parent, nil
}
