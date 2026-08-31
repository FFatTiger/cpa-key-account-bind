package main

import (
	"encoding/json"
	"fmt"
)

const pluginName = "key-account-bind"

// pluginVersion is overridden at release time via -ldflags -X main.pluginVersion=...
var pluginVersion = "0.3.0"

// handleConfigure implements plugin.register / plugin.reconfigure.
func handleConfigure(req []byte) []byte {
	var lr lifecycleRequest
	if len(req) > 0 {
		if err := json.Unmarshal(req, &lr); err != nil {
			return errorEnvelope("invalid_request", "bad lifecycle payload: "+err.Error())
		}
	}
	p, err := parsePolicy(lr.ConfigYAML)
	if err != nil {
		return errorEnvelope("invalid_config", err.Error())
	}
	state.Store(p)
	selections.reset()
	return okEnvelope(registrationResponse{
		SchemaVersion: 1,
		Metadata: registrationMetadata{
			Name:             pluginName,
			Version:          pluginVersion,
			Author:           "FFatTiger",
			GitHubRepository: "https://github.com/FFatTiger/cpa-key-account-bind",
			Description:      "Bind downstream API keys to specific upstream credentials (auth files) at scheduler.pick time.",
			ConfigFields: []configField{
				{
					Name:        "bindings",
					Type:        "array",
					Description: "Per-key bindings, one entry per line: key=allowGlob1,allowGlob2 (globs match auth file names, case-insensitive). Compact form: \"sk-a=team-*.json,vip-*\"",
				},
				{
					Name:        "unbound",
					Type:        "enum",
					EnumValues:  []string{"passthrough", "deny"},
					Description: "What to do with downstream keys that have no binding: passthrough (host native scheduling) or deny.",
				},
				{
					Name:        "strategy",
					Type:        "enum",
					EnumValues:  []string{strategyRoundRobin, strategyWeightedRoundRobin, strategyFillFirst},
					Description: "Scheduling strategy inside each key's allowed credential set. Mirrors CPA routing.strategy; default is round-robin.",
				},
			},
		},
		Capabilities: registrationCapability{Scheduler: true},
	})
}

// handlePick implements scheduler.pick.
//
// Decision table:
//
//	downstream key | binding | outcome
//	----------------+---------+-------------------------------------------
//	(none found)    | -       | Handled=false (host native scheduling)
//	present         | none    | unbound=passthrough -> Handled=false
//	                |         | unbound=deny       -> error (key_not_bound)
//	present         | set     | filter candidates by allow globs;
//	                        |   empty result -> error (auth_not_bound) = FAIL
//	                        |   else apply strategy inside the allowed set
//
// Errors (not Handled=false) make the host fail the request outright; it
// never reschedules on its own after a scheduler error. That is the isolation
// guarantee: a bound key either lands on an allowed credential or the request
// fails loudly.
func handlePick(req []byte) []byte {
	var pr schedulerPickRequest
	if err := json.Unmarshal(req, &pr); err != nil {
		return errorEnvelope("invalid_request", "bad scheduler payload: "+err.Error())
	}
	p := state.Load()
	if p == nil {
		// Not configured (yet): never gate traffic.
		return okEnvelope(schedulerPickResponse{Handled: false})
	}

	key := extractDownstreamKey(pr.Options.Headers)
	if key == "" {
		// Caller identity not visible from headers (e.g. query-param key or
		// internal calls). We cannot enforce a binding, so defer to host.
		return okEnvelope(schedulerPickResponse{Handled: false})
	}

	b := p.bindingFor(key)
	if b == nil {
		if p.unboundPassthrough {
			return okEnvelope(schedulerPickResponse{Handled: false})
		}
		return errorEnvelope("key_not_bound",
			fmt.Sprintf("key-account-bind: downstream key is not bound to any credential group (unbound=deny)"))
	}

	allowed := make([]schedulerAuthCandidate, 0, len(pr.Candidates))
	for _, cand := range pr.Candidates {
		if !b.matches(cand.ID) {
			continue
		}
		if !candidateUsable(cand.Status) {
			continue
		}
		allowed = append(allowed, cand)
	}
	if len(allowed) == 0 {
		// Isolation guard: DO NOT return Handled=false here — that would let
		// the host schedule any candidate and silently break isolation.
		return errorEnvelope("auth_not_bound",
			fmt.Sprintf("key-account-bind: no eligible credential for this key among %d candidate(s)", len(pr.Candidates)))
	}

	picked, ok := selectAllowed(p.strategy, selectionScope(key, pr), allowed, requestProviders(pr))
	if !ok {
		return errorEnvelope("auth_unavailable",
			fmt.Sprintf("key-account-bind: no eligible credential for strategy %s", p.strategy))
	}
	return okEnvelope(schedulerPickResponse{AuthID: picked.ID, Handled: true})
}
