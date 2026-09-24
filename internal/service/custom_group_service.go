package service

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"hyperdns/internal/core/matcher"
	"hyperdns/internal/database"
)

// CustomGroupService owns the operator's named custom policy groups: it loads
// them from the database, keeps the matcher's view in sync, and serves the
// dashboard's CRUD. The matcher holds the authoritative in-memory copy for
// resolution; this service is the write path and the source of truth on disk.
type CustomGroupService struct {
	db      *database.DB
	matcher *matcher.Matcher
	mu      sync.Mutex
}

// ErrCustomGroupNotFound re-exports the storage sentinel so the HTTP layer maps
// it to 404 without importing the database package.
var ErrCustomGroupNotFound = database.ErrCustomGroupNotFound

// validActions is the closed set a group may carry. A typo must be refused at
// the write, not silently coerced into a proxy rule that relays traffic nobody
// asked to relay.
var validActions = map[string]bool{"proxy": true, "direct": true, "block": true}

func NewCustomGroupService(db *database.DB, m *matcher.Matcher) *CustomGroupService {
	s := &CustomGroupService{db: db, matcher: m}
	s.reload()
	return s
}

// actionOf maps the stored string to the matcher action. Unknown strings resolve
// to proxy, matching the matcher's own default, but writes are validated so an
// unknown value never reaches storage.
func actionOf(a string) matcher.Action {
	switch strings.ToLower(strings.TrimSpace(a)) {
	case "block":
		return matcher.ActionBlock
	case "direct":
		return matcher.ActionDirect
	default:
		return matcher.ActionProxy
	}
}

// reload pushes the stored groups into the matcher. Called at startup and after
// every mutation, so the resolver and the database never disagree.
func (s *CustomGroupService) reload() {
	groups, err := s.db.ListCustomGroups()
	if err != nil {
		return
	}
	mg := make([]matcher.CustomGroup, 0, len(groups))
	for _, g := range groups {
		mg = append(mg, matcher.CustomGroup{
			Name:    g.Name,
			Action:  actionOf(g.Action),
			Domains: g.Domains,
			Enabled: g.Enabled,
		})
	}
	s.matcher.SetCustomGroups(mg)
}

// List returns every stored group for the dashboard.
func (s *CustomGroupService) List() ([]database.CustomPolicyGroup, error) {
	return s.db.ListCustomGroups()
}

// normalizeDomains trims, lowercases and drops blanks and duplicates. An empty
// result is an error: a group that matches nothing is a mistake, not a rule.
func normalizeDomains(in []string) ([]string, error) {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, d := range in {
		d = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(d, ".")))
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	if len(out) == 0 {
		return nil, errors.New("a custom group needs at least one domain")
	}
	return out, nil
}

// Create validates and stores a new group, then re-applies to the matcher.
func (s *CustomGroupService) Create(name, action string, domains []string, enabled bool) (*database.CustomPolicyGroup, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("a custom group needs a name")
	}
	action = strings.ToLower(strings.TrimSpace(action))
	if !validActions[action] {
		return nil, fmt.Errorf("invalid action %q (use proxy, direct or block)", action)
	}
	norm, err := normalizeDomains(domains)
	if err != nil {
		return nil, err
	}

	idBytes := make([]byte, 8)
	_, _ = rand.Read(idBytes)
	g := database.CustomPolicyGroup{
		ID:        hex.EncodeToString(idBytes),
		Name:      name,
		Action:    action,
		Domains:   norm,
		Enabled:   enabled,
		CreatedAt: time.Now(),
	}
	if err := s.db.SaveCustomGroup(g); err != nil {
		return nil, err
	}
	s.reload()
	return &g, nil
}

// Update replaces the mutable fields of an existing group.
func (s *CustomGroupService) Update(id, name, action string, domains []string, enabled bool) (*database.CustomPolicyGroup, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	groups, err := s.db.ListCustomGroups()
	if err != nil {
		return nil, err
	}
	var existing *database.CustomPolicyGroup
	for i := range groups {
		if groups[i].ID == id {
			existing = &groups[i]
			break
		}
	}
	if existing == nil {
		return nil, ErrCustomGroupNotFound
	}

	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("a custom group needs a name")
	}
	action = strings.ToLower(strings.TrimSpace(action))
	if !validActions[action] {
		return nil, fmt.Errorf("invalid action %q (use proxy, direct or block)", action)
	}
	norm, err := normalizeDomains(domains)
	if err != nil {
		return nil, err
	}

	existing.Name = name
	existing.Action = action
	existing.Domains = norm
	existing.Enabled = enabled
	if err := s.db.SaveCustomGroup(*existing); err != nil {
		return nil, err
	}
	s.reload()
	return existing, nil
}

// Delete removes a group and re-applies.
func (s *CustomGroupService) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.db.DeleteCustomGroup(id); err != nil {
		return err
	}
	s.reload()
	return nil
}
