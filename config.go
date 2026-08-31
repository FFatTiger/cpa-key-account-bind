package main

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// pluginConfig is the YAML under plugins.configs.key-account-bind.
//
//	bindings:
//	  - key: "sk-tenant-a"                # must also exist in native api-keys
//	    allow: ["codex-a*.json", "claude-main*"]   # glob on auth file / auth ID
//	  - key: "sk-tenant-b"
//	    allow: ["codex-b*"]
//	unbound: passthrough   # passthrough | deny  (default passthrough)
type pluginConfig struct {
	Bindings bindingList `yaml:"bindings"`
	Unbound  string      `yaml:"unbound"`
}

// bindingList accepts either compact string entries or full object entries:
//
//	bindings:
//	  - "sk-tenant-a=team-*.json,vip-*"          # compact: key=glob1,glob2
//	  - key: "sk-tenant-b"                        # verbose object form
//	    allow: ["codex-b*"]
//
// The compact form keeps the whole config editable from the CPAMC plugin
// panel, which only supports string arrays natively.
type bindingList []bindingRule

func (l *bindingList) UnmarshalYAML(node *yaml.Node) error {
	*l = nil
	for i, item := range node.Content {
		var rule bindingRule
		switch item.Tag {
		case "!!str":
			parts := strings.SplitN(item.Value, "=", 2)
			if len(parts) != 2 {
				return fmt.Errorf("bindings[%d]: compact entry must be \"key=glob1,glob2\"", i)
			}
			rule.Key = strings.TrimSpace(parts[0])
			for _, a := range strings.Split(parts[1], ",") {
				if a = strings.TrimSpace(a); a != "" {
					rule.Allow = append(rule.Allow, a)
				}
			}
		case "!!map":
			if err := item.Decode(&rule); err != nil {
				return fmt.Errorf("bindings[%d]: %w", i, err)
			}
		default:
			return fmt.Errorf("bindings[%d]: must be a string or a mapping", i)
		}
		*l = append(*l, rule)
	}
	return nil
}

type bindingRule struct {
	Key   string   `yaml:"key"`
	Allow []string `yaml:"allow"`
}

// policy is the immutable, compiled form of pluginConfig.
type policy struct {
	// byKey maps lowercase downstream key -> allowed-ID matcher set.
	byKey map[string]*binding
	// unboundPassthrough: keys not present in byKey fall back to the host
	// scheduler. When false, unknown-but-natively-valid keys are denied.
	unboundPassthrough bool
}

type binding struct {
	patterns []string // normalized (lowercase) glob patterns
}

// matches reports whether an auth ID (lowercased) is allowed by the binding.
func (b *binding) matches(id string) bool {
	if b == nil {
		return false
	}
	id = strings.ToLower(id)
	for _, p := range b.patterns {
		if ok, err := path.Match(p, id); err == nil && ok {
			return true
		}
	}
	return false
}

func defaultPolicy() *policy {
	return &policy{byKey: map[string]*binding{}, unboundPassthrough: true}
}

func parsePolicy(raw []byte) (*policy, error) {
	var cfg pluginConfig
	if len(raw) > 0 {
		if err := yaml.Unmarshal(raw, &cfg); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	}
	p := &policy{byKey: make(map[string]*binding, len(cfg.Bindings))}
	switch strings.ToLower(strings.TrimSpace(cfg.Unbound)) {
	case "", "passthrough":
		p.unboundPassthrough = true
	case "deny":
		p.unboundPassthrough = false
	default:
		return nil, fmt.Errorf("invalid unbound policy %q (want passthrough or deny)", cfg.Unbound)
	}
	for i, rule := range cfg.Bindings {
		key := strings.TrimSpace(rule.Key)
		if key == "" {
			return nil, fmt.Errorf("bindings[%d]: key is required", i)
		}
		patterns := make([]string, 0, len(rule.Allow))
		for _, a := range rule.Allow {
			a = strings.ToLower(strings.TrimSpace(a))
			if a == "" {
				continue
			}
			if _, err := path.Match(a, "x"); err != nil {
				return nil, fmt.Errorf("bindings[%d]: invalid glob %q: %w", i, a, err)
			}
			patterns = append(patterns, a)
		}
		if len(patterns) == 0 {
			return nil, fmt.Errorf("bindings[%d]: at least one allow pattern is required", i)
		}
		lk := strings.ToLower(key)
		if _, dup := p.byKey[lk]; dup {
			return nil, fmt.Errorf("bindings[%d]: duplicate key", i)
		}
		p.byKey[lk] = &binding{patterns: patterns}
	}
	return p, nil
}

// bindingFor returns the binding for a downstream key, or nil when unbound.
func (p *policy) bindingFor(key string) *binding {
	if p == nil || key == "" {
		return nil
	}
	return p.byKey[strings.ToLower(strings.TrimSpace(key))]
}

// validateConfig is used by tests to assert compile-time config errors.
func validateConfig(raw []byte) error {
	_, err := parsePolicy(raw)
	return err
}

// sortedKeys is a test/diagnostic helper.
func (p *policy) sortedKeys() []string {
	if p == nil {
		return nil
	}
	out := make([]string, 0, len(p.byKey))
	for k := range p.byKey {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
