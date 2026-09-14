package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// Account isolation is enforced by the scheduler plugin while it is enabled.
type isolationConfig struct {
	RequireScopeBoundKey *bool             `yaml:"require-scope-bound-key"`
	Enabled              bool              `yaml:"enabled"`
	StateFile            string            `yaml:"state-file"`
	MaxSessions          int               `yaml:"max-sessions"`
	Credentials          []credentialClass `yaml:"credentials"`
}
type credentialClass struct {
	ID       string `yaml:"id"`
	Provider string `yaml:"provider"`
	Scope    string `yaml:"scope"`
	Source   string `yaml:"source"`
}
type isolationPolicy struct {
	requireScopeBoundKey bool
	file                 string
	limit                int
	classes              map[string]credentialClass
}
type sessionBinding struct {
	Scope  string `json:"scope"`
	Parent string `json:"parent,omitempty"`
}
type sessionFile struct {
	Checksum string                    `json:"checksum"`
	Version  int                       `json:"version"`
	Sessions map[string]sessionBinding `json:"sessions"`
}

// Serialize reads, checks, and durable writes across policy reloads. No TTL or
// eviction: forgetting an identity could authorize a resumed tree in a new scope.
var isolationMu sync.Mutex
var routeComponent = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
var stateID = regexp.MustCompile(`^[a-f0-9]{64}$`)

// Scope strings are ASCII route components, so each byte has a fixed JSON cost.
// Include a parent hash and separator for every entry to bound the largest store.
const maxScopeLength = 64
const maxSessionBindingBytes = 64 + maxScopeLength + 64 + len(`"":{"scope":"","parent":""},`)
const stateEnvelopeBytes = 64 + len(`{"checksum":"","version":1,"sessions":{}}`)

func (p *isolationPolicy) maxStateBytes() int64 {
	return int64(p.limit)*int64(maxSessionBindingBytes) + int64(stateEnvelopeBytes)
}

func compileIsolation(c isolationConfig) (*isolationPolicy, error) {
	if !c.Enabled {
		return nil, nil
	}
	if !filepath.IsAbs(c.StateFile) {
		return nil, errors.New("isolation state-file must be absolute")
	}
	if c.MaxSessions == 0 {
		c.MaxSessions = 100000
	}
	if c.MaxSessions < 1 || c.MaxSessions > 1000000 {
		return nil, errors.New("invalid max-sessions")
	}
	p := &isolationPolicy{file: c.StateFile, limit: c.MaxSessions, classes: map[string]credentialClass{}}
	p.requireScopeBoundKey = c.RequireScopeBoundKey == nil || *c.RequireScopeBoundKey
	for _, x := range c.Credentials {
		if x.ID == "" || x.Provider == "" || (len(x.Scope) > maxScopeLength || !routeComponent.MatchString(x.Scope)) || !routeComponent.MatchString(x.Source) {
			return nil, errors.New("credential requires exact id, provider, scope and source")
		}
		if _, ok := p.classes[x.ID]; ok {
			return nil, errors.New("duplicate credential classification")
		}
		p.classes[x.ID] = x
	}
	if len(p.classes) == 0 {
		return nil, errors.New("isolation requires credential classifications")
	}
	return p, nil
}

func sessionHash(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

func (p *isolationPolicy) readState() (sessionFile, error) {
	var s sessionFile
	f, err := os.Open(p.file)
	if err != nil {
		return s, errors.New("isolation state unavailable")
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Size() > p.maxStateBytes() {
		return s, errors.New("invalid isolation state file")
	}
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err = dec.Decode(&s); err != nil || s.Version != 1 || s.Sessions == nil || len(s.Sessions) > p.limit {
		return s, errors.New("invalid isolation state")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return s, errors.New("trailing isolation state")
	}
	data, _ := json.Marshal(s.Sessions)
	sum := sha256.Sum256(data)
	if s.Checksum != hex.EncodeToString(sum[:]) {
		return s, errors.New("isolation state checksum mismatch")
	}
	for id, b := range s.Sessions {
		if !stateID.MatchString(id) || (len(b.Scope) > maxScopeLength || !routeComponent.MatchString(b.Scope)) || (b.Parent != "" && !stateID.MatchString(b.Parent)) {
			return s, errors.New("invalid session binding")
		}
		if b.Parent != "" {
			parent, ok := s.Sessions[b.Parent]
			if !ok || parent.Scope != b.Scope || b.Parent == id {
				return s, errors.New("invalid parent binding")
			}
		}
	}
	return s, nil
}

func (p *isolationPolicy) writeState(s sessionFile) error {
	payload, _ := json.Marshal(s.Sessions)
	sum := sha256.Sum256(payload)
	s.Checksum = hex.EncodeToString(sum[:])
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	// Never replace a usable store with bytes the next read would reject.
	if int64(len(data)) > p.maxStateBytes() {
		return errors.New("isolation state exceeds byte limit")
	}
	f, err := os.CreateTemp(filepath.Dir(p.file), ".scope-state-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, p.file); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(p.file))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (p *isolationPolicy) filter(pr schedulerPickRequest, b *binding) ([]schedulerAuthCandidate, error) {
	sid, parent, sessionErr := requestSession(pr.Options)
	if sessionErr != nil {
		return nil, sessionErr
	}
	parts := strings.SplitN(canonicalModelKey(pr.Model), "/", 3)
	if len(parts) != 3 || !routeComponent.MatchString(parts[0]) || !routeComponent.MatchString(parts[1]) || parts[2] == "" {
		return nil, errors.New("explicit scope/source/model route required")
	}
	scope, source := parts[0], parts[1]
	if p.requireScopeBoundKey {
		if b == nil {
			return nil, errors.New("scope-bound downstream key required")
		}
		keyScope := ""
		for _, class := range p.classes {
			if b.matches(class.ID) {
				if keyScope != "" && keyScope != class.Scope {
					return nil, errors.New("downstream binding spans account scopes")
				}
				keyScope = class.Scope
			}
		}
		if keyScope != scope {
			return nil, errors.New("downstream key scope mismatch")
		}
	}
	allowed := make([]schedulerAuthCandidate, 0, len(pr.Candidates))
	for _, c := range pr.Candidates {
		class, ok := p.classes[c.ID]
		if !ok || class.Provider != c.Provider || class.Scope != scope || class.Source != source || !candidateUsable(c.Status) || (b != nil && !b.matches(c.ID)) {
			continue
		}
		allowed = append(allowed, c)
	}
	if len(allowed) == 0 {
		return nil, errors.New("no authorized credential for requested scope/source")
	}
	isolationMu.Lock()
	defer isolationMu.Unlock()
	lock, err := os.OpenFile(p.file+".lock", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, errors.New("isolation state locked or unavailable")
	}
	lock.Close()
	defer os.Remove(p.file + ".lock")
	s, err := p.readState()
	if err != nil {
		return nil, err
	}
	id := sessionHash(sid)
	pid := ""
	if parent != "" {
		pid = sessionHash(parent)
	}
	if old, ok := s.Sessions[id]; ok {
		if old.Scope != scope || old.Parent != pid {
			return nil, errors.New("immutable tree scope or parent mismatch")
		}
		return allowed, nil
	}
	if pid != "" {
		old, ok := s.Sessions[pid]
		if !ok || old.Scope != scope {
			return nil, errors.New("unknown parent or cross-scope descendant")
		}
	}
	if len(s.Sessions) >= p.limit {
		return nil, errors.New("isolation state capacity reached")
	}
	s.Sessions[id] = sessionBinding{Scope: scope, Parent: pid}
	if err = p.writeState(s); err != nil {
		return nil, fmt.Errorf("cannot persist isolation decision")
	}
	return allowed, nil
}
