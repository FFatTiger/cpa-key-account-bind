package main

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const (
	strategyRoundRobin         = "round-robin"
	strategyWeightedRoundRobin = "weighted-round-robin"
	strategyFillFirst          = "fill-first"
	maxSelectionScopes         = 4096
)

// selectionState mirrors CPA's built-in selectors inside a bound key's
// filtered candidate set. The current plugin ABI cannot return a filtered set
// and then delegate to the native selector, so this state is local.
type selectionState struct {
	mu          sync.Mutex
	lastPick    map[string]string
	mixedCursor map[string]int
	weighted    map[string]*weightedState
}

type weightedState struct {
	current map[string]int64
	weights map[string]int64
}

var selections selectionState

func (s *selectionState) reset() {
	s.mu.Lock()
	s.lastPick = make(map[string]string)
	s.mixedCursor = make(map[string]int)
	s.weighted = make(map[string]*weightedState)
	s.mu.Unlock()
}

func selectAllowed(strategy, scope string, candidates []schedulerAuthCandidate, providers []string) (schedulerAuthCandidate, bool) {
	candidates = highestPriorityCandidates(candidates)
	if len(candidates) == 0 {
		return schedulerAuthCandidate{}, false
	}
	providers = normalizedProviders(providers, candidates)

	selections.mu.Lock()
	defer selections.mu.Unlock()
	selections.ensureMapsLocked()

	switch strategy {
	case strategyFillFirst:
		return pickFillFirst(candidates, providers)
	case strategyWeightedRoundRobin:
		return selections.pickWeightedLocked(scope, orderByID(candidates))
	default:
		if len(providers) > 1 {
			return selections.pickMixedRoundRobinLocked(scope, candidates, providers)
		}
		return selections.pickRoundRobinLocked(scope, orderByID(candidates)), true
	}
}

func (s *selectionState) ensureMapsLocked() {
	if s.lastPick == nil {
		s.lastPick = make(map[string]string)
	}
	if s.mixedCursor == nil {
		s.mixedCursor = make(map[string]int)
	}
	if s.weighted == nil {
		s.weighted = make(map[string]*weightedState)
	}
}

func (s *selectionState) ensureLastPickScopeLocked(scope string) {
	if _, exists := s.lastPick[scope]; !exists && len(s.lastPick) >= maxSelectionScopes {
		s.lastPick = make(map[string]string)
	}
}

func (s *selectionState) ensureMixedScopeLocked(scope string) {
	if _, exists := s.mixedCursor[scope]; !exists && len(s.mixedCursor) >= maxSelectionScopes {
		s.mixedCursor = make(map[string]int)
	}
}

func (s *selectionState) ensureWeightedScopeLocked(scope string) {
	if _, exists := s.weighted[scope]; !exists && len(s.weighted) >= maxSelectionScopes {
		s.weighted = make(map[string]*weightedState)
	}
}

func highestPriorityCandidates(candidates []schedulerAuthCandidate) []schedulerAuthCandidate {
	if len(candidates) == 0 {
		return nil
	}
	maxPriority := candidates[0].Priority
	for _, candidate := range candidates[1:] {
		if candidate.Priority > maxPriority {
			maxPriority = candidate.Priority
		}
	}
	out := make([]schedulerAuthCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Priority == maxPriority {
			out = append(out, candidate)
		}
	}
	return out
}

func orderByID(candidates []schedulerAuthCandidate) []schedulerAuthCandidate {
	out := append([]schedulerAuthCandidate(nil), candidates...)
	// CPA's built-in selectors receive an auth-ID-sorted slice.
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func normalizedProviders(configured []string, candidates []schedulerAuthCandidate) []string {
	out := make([]string, 0, len(configured))
	seen := make(map[string]struct{}, len(configured))
	add := func(provider string) {
		provider = strings.ToLower(strings.TrimSpace(provider))
		if provider == "" || provider == "mixed" {
			return
		}
		if _, exists := seen[provider]; exists {
			return
		}
		seen[provider] = struct{}{}
		out = append(out, provider)
	}
	for _, provider := range configured {
		add(provider)
	}
	if len(out) == 0 {
		for _, candidate := range candidates {
			add(candidate.Provider)
		}
		sort.Strings(out)
	}
	return out
}

func candidatesForProvider(candidates []schedulerAuthCandidate, provider string) []schedulerAuthCandidate {
	provider = strings.ToLower(strings.TrimSpace(provider))
	out := make([]schedulerAuthCandidate, 0)
	for _, candidate := range candidates {
		if strings.ToLower(strings.TrimSpace(candidate.Provider)) == provider {
			out = append(out, candidate)
		}
	}
	return orderByID(out)
}

func pickFillFirst(candidates []schedulerAuthCandidate, providers []string) (schedulerAuthCandidate, bool) {
	if len(providers) <= 1 {
		ordered := orderByID(candidates)
		if len(ordered) == 0 {
			return schedulerAuthCandidate{}, false
		}
		return ordered[0], true
	}
	// CPA mixed fill-first walks providers in configured order and then picks
	// the first auth ID in that provider's highest-priority bucket.
	for _, provider := range providers {
		ordered := candidatesForProvider(candidates, provider)
		if len(ordered) > 0 {
			return ordered[0], true
		}
	}
	return schedulerAuthCandidate{}, false
}

func (s *selectionState) pickRoundRobinLocked(scope string, ordered []schedulerAuthCandidate) schedulerAuthCandidate {
	s.ensureLastPickScopeLocked(scope)
	last := s.lastPick[scope]
	index := 0
	if last != "" {
		index = sort.Search(len(ordered), func(i int) bool { return ordered[i].ID > last })
		if index >= len(ordered) {
			index = 0
		}
	}
	picked := ordered[index]
	s.lastPick[scope] = picked.ID
	return picked
}

func (s *selectionState) pickMixedRoundRobinLocked(scope string, candidates []schedulerAuthCandidate, providers []string) (schedulerAuthCandidate, bool) {
	s.ensureMixedScopeLocked(scope)
	groups := make([][]schedulerAuthCandidate, len(providers))
	counts := make([]int, len(providers))
	starts := make([]int, len(providers))
	ends := make([]int, len(providers))
	total := 0
	for i, provider := range providers {
		starts[i] = total
		groups[i] = candidatesForProvider(candidates, provider)
		counts[i] = len(groups[i])
		total += counts[i]
		ends[i] = total
	}
	if total == 0 {
		return schedulerAuthCandidate{}, false
	}

	startSlot := s.mixedCursor[scope] % total
	startProvider := -1
	for i := range providers {
		if counts[i] > 0 && startSlot < ends[i] {
			startProvider = i
			break
		}
	}
	if startProvider < 0 {
		return schedulerAuthCandidate{}, false
	}

	slot := startSlot
	for offset := 0; offset < len(providers); offset++ {
		providerIndex := (startProvider + offset) % len(providers)
		if counts[providerIndex] == 0 {
			continue
		}
		if providerIndex != startProvider {
			slot = starts[providerIndex]
		}
		providerScope := scope + "|provider:" + providers[providerIndex]
		picked := s.pickRoundRobinLocked(providerScope, groups[providerIndex])
		s.mixedCursor[scope] = slot + 1
		return picked, true
	}
	return schedulerAuthCandidate{}, false
}

func (s *selectionState) pickWeightedLocked(scope string, ordered []schedulerAuthCandidate) (schedulerAuthCandidate, bool) {
	s.ensureWeightedScopeLocked(scope)
	state := s.weighted[scope]
	if state == nil {
		state = &weightedState{}
		s.weighted[scope] = state
	}
	weights := make(map[string]int64, len(ordered))
	for _, candidate := range ordered {
		if weight := candidateWeight(candidate); weight > 0 {
			weights[candidate.ID] = weight
		}
	}
	state.prepare(weights)

	pickedIndex := -1
	var pickedCurrent int64
	var totalWeight int64
	for i, candidate := range ordered {
		weight := weights[candidate.ID]
		if weight <= 0 {
			continue
		}
		state.current[candidate.ID] = saturatingAdd(state.current[candidate.ID], weight)
		totalWeight = saturatingAdd(totalWeight, weight)
		if pickedIndex < 0 || state.current[candidate.ID] > pickedCurrent {
			pickedIndex = i
			pickedCurrent = state.current[candidate.ID]
		}
	}
	if pickedIndex < 0 {
		return schedulerAuthCandidate{}, false
	}
	picked := ordered[pickedIndex]
	state.current[picked.ID] = saturatingAdd(state.current[picked.ID], -totalWeight)
	return picked, true
}

func (s *weightedState) prepare(weights map[string]int64) {
	if s.current == nil || weightsChanged(s.weights, weights) {
		s.current = make(map[string]int64, len(weights))
	}
	if s.weights == nil {
		s.weights = make(map[string]int64, len(weights))
	}
	for key, weight := range weights {
		s.weights[key] = weight
	}
	if len(s.current) > 1024 || len(s.weights) > 1024 {
		for key := range s.current {
			if _, ok := weights[key]; !ok {
				delete(s.current, key)
			}
		}
		for key := range s.weights {
			if _, ok := weights[key]; !ok {
				delete(s.weights, key)
			}
		}
	}
}

func weightsChanged(left, right map[string]int64) bool {
	if len(left) == 0 {
		return false
	}
	for key, weight := range right {
		if previous, ok := left[key]; ok && previous != weight {
			return true
		}
	}
	return false
}

func candidateWeight(candidate schedulerAuthCandidate) int64 {
	if candidate.Attributes == nil {
		return 1
	}
	raw := strings.TrimSpace(candidate.Attributes["weight"])
	if raw == "" {
		return 1
	}
	weight, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || weight <= 0 || weight > 1_000_000 {
		return 0
	}
	return weight
}

func requestProviders(req schedulerPickRequest) []string {
	providers := make([]string, 0, len(req.Providers)+1)
	if strings.TrimSpace(req.Provider) != "" {
		providers = append(providers, req.Provider)
	}
	providers = append(providers, req.Providers...)
	return normalizedProviders(providers, req.Candidates)
}

func selectionScope(key string, req schedulerPickRequest) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(key)))
	providers := requestProviders(req)
	return hex.EncodeToString(sum[:8]) + "|" + strings.Join(providers, ",") + "|" + canonicalModelKey(req.Model)
}

// canonicalModelKey mirrors CPA thinking.ParseSuffix + canonicalModelKey: the
// final parenthesized thinking suffix does not create a separate rotation.
func canonicalModelKey(model string) string {
	model = strings.TrimSpace(model)
	lastOpen := strings.LastIndex(model, "(")
	if lastOpen >= 0 && strings.HasSuffix(model, ")") {
		if base := strings.TrimSpace(model[:lastOpen]); base != "" {
			return base
		}
	}
	return model
}

func saturatingAdd(value, delta int64) int64 {
	if delta > 0 && value > math.MaxInt64-delta {
		return math.MaxInt64
	}
	if delta < 0 && value < math.MinInt64-delta {
		return math.MinInt64
	}
	return value + delta
}
