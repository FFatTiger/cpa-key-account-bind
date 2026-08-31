package main

import (
	"net/http"
	"strings"
)

// extractDownstreamKey pulls the downstream API key out of the original
// request headers the host forwards to scheduler.pick (Options.Headers).
//
// Supported header spellings mirror what CPA's native api-key auth accepts:
// Authorization: Bearer <key>, X-API-Key / x-api-key / api-key, and
// x-goog-api-key (Gemini CLI style). Query-parameter keys (?key= / ?api_key=)
// are NOT visible to scheduler.pick (the host passes headers only), so keys
// used with bindings must authenticate via headers.
func extractDownstreamKey(headers map[string][]string) string {
	if len(headers) == 0 {
		return ""
	}
	get := func(name string) string {
		if v, ok := lookupHeader(headers, name); ok {
			return v
		}
		return ""
	}
	if auth := get("Authorization"); auth != "" {
		if token := bearerToken(auth); token != "" {
			return token
		}
		return ""
	}
	for _, name := range []string{"X-API-Key", "x-api-key", "api-key", "X-Goog-Api-Key", "x-goog-api-key"} {
		if v := get(name); v != "" {
			return v
		}
	}
	return ""
}

// lookupHeader does a case-insensitive canonical-ish lookup over the raw map
// the ABI gives us (host sends http.Header's map form; keys may be any case).
func lookupHeader(headers map[string][]string, name string) (string, bool) {
	if values, ok := headers[name]; ok && len(values) > 0 && strings.TrimSpace(values[0]) != "" {
		return strings.TrimSpace(values[0]), true
	}
	for k, values := range headers {
		if strings.EqualFold(k, name) && len(values) > 0 && strings.TrimSpace(values[0]) != "" {
			return strings.TrimSpace(values[0]), true
		}
	}
	return "", false
}

func bearerToken(value string) string {
	parts := strings.Fields(value)
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return strings.TrimSpace(parts[1])
	}
	return ""
}

// candidateUsable mirrors the host's usable-status filter. Unknown status
// strings are treated as usable — the host already excluded hard-failed auths
// from the candidate list before calling us; this is defense in depth.
func candidateUsable(status string) bool {
	s := normalizeStatus(status)
	switch s {
	case "disabled", "error", "expired", "revoked", "invalid", "unavailable",
		"cooldown", "cooling_down", "quota_exhausted", "exhausted", "blocked":
		return false
	default:
		return true
	}
}

func normalizeStatus(status string) string {
	s := strings.ToLower(strings.TrimSpace(status))
	s = strings.NewReplacer("-", "_", " ", "_").Replace(s)
	return s
}

// ensure http.Header is used in tests only via this alias to avoid an unused
// import in the main build when tests change.
var _ = http.Header{}
