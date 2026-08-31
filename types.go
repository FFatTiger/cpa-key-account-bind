package main

// Wire types for the CLIProxyAPI native plugin ABI. Field names intentionally
// have NO json tags: the host marshals its pluginapi structs with Go field
// names (PascalCase), and Go's encoding/json matches case-insensitively on
// decode, so PascalCase here is exact.

const (
	methodRegister      = "plugin.register"
	methodReconfigure   = "plugin.reconfigure"
	methodSchedulerPick = "scheduler.pick"
)

type lifecycleRequest struct {
	ConfigYAML    []byte `json:"config_yaml"`
	SchemaVersion uint32 `json:"schema_version"`
}

type registrationResponse struct {
	SchemaVersion uint32                 `json:"schema_version"`
	Metadata      registrationMetadata   `json:"metadata"`
	Capabilities  registrationCapability `json:"capabilities"`
}

type registrationMetadata struct {
	Name             string `json:"Name"`
	Version          string `json:"Version"`
	Author           string `json:"Author"`
	GitHubRepository string `json:"GitHubRepository"`
	Description      string `json:"Description,omitempty"`
}

type registrationCapability struct {
	Scheduler bool `json:"scheduler"`
}

type schedulerPickRequest struct {
	Provider   string                   `json:"Provider"`
	Providers  []string                 `json:"Providers"`
	Model      string                   `json:"Model"`
	Stream     bool                     `json:"Stream"`
	Options    schedulerPickOptions     `json:"Options"`
	Candidates []schedulerAuthCandidate `json:"Candidates"`
}

type schedulerPickOptions struct {
	Headers  map[string][]string `json:"Headers"`
	Metadata map[string]any      `json:"Metadata"`
}

type schedulerAuthCandidate struct {
	ID         string            `json:"ID"`
	Provider   string            `json:"Provider"`
	Priority   int               `json:"Priority"`
	Status     string            `json:"Status"`
	Attributes map[string]string `json:"Attributes"`
	Metadata   map[string]any    `json:"Metadata"`
}

type schedulerPickResponse struct {
	AuthID string `json:"AuthID"`
	// DelegateBuiltin intentionally unused: delegation would let the host
	// schedule over the FULL candidate set, breaking isolation.
	DelegateBuiltin string `json:"DelegateBuiltin,omitempty"`
	Handled         bool   `json:"Handled"`
}
