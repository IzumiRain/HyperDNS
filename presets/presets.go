// Package presets loads the built-in policy catalog from the JSON files that
// live beside it. The files are the single source of truth for the preset
// channel (v2.3.0): the daemon embeds them as the always-works offline
// baseline, and the same files are what the Pages channel signs and publishes.
//
// The data is compile-time embedded — a corrupted file fails the package's
// tests in CI, and a broken edit cannot ship in a binary that passes them.
package presets

import (
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

//go:embed *.json
var data embed.FS

// Kind describes what the matcher does with a policy's domains.
const (
	// KindProxy spoofs matched names to the operator's SNI proxy.
	KindProxy = "proxy"
	// KindBlock sinkholes matched names (adblock / familysafe).
	KindBlock = "block"
	// KindVeto is the downloads plane: not an action index, only the set the
	// downloads switch can pull back out of the proxy path.
	KindVeto = "veto"
)

// Preset is one policy file. Field order and JSON tags are the channel format —
// tools/genpresets writes this shape, preset-validate checks it, and the Pages
// manifest references these files by ID.
type Preset struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Key            string   `json:"key"` // dashboard/config toggle key, e.g. "enable_riot"
	Category       string   `json:"category"`
	Kind           string   `json:"kind"`
	Icon           string   `json:"icon"` // relative to the channel manifest's base_url
	Homepage       string   `json:"homepage,omitempty"`
	DefaultEnabled bool     `json:"default_enabled"`
	SortOrder      int      `json:"sort_order"`
	Version        int      `json:"version"`
	UpdatedAt      string   `json:"updated_at"` // ISO 8601
	Domains        []string `json:"domains"`
	Notes          string   `json:"notes,omitempty"`
}

var cached = mustLoad()

// mustLoad parses every embedded policy file once. Embedded data is compile-time
// constant, so a panic here means the tree itself is broken — there is no
// runtime recovery path to fall back to and none should be invented: refusing to
// start with a policy catalog that does not parse is the safe direction.
func mustLoad() []Preset {
	entries, err := data.ReadDir(".")
	if err != nil {
		panic(fmt.Sprintf("presets: read embedded dir: %v", err))
	}
	out := make([]Preset, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := data.ReadFile(e.Name())
		if err != nil {
			panic(fmt.Sprintf("presets: read %s: %v", e.Name(), err))
		}
		var p Preset
		if err := json.Unmarshal(raw, &p); err != nil {
			panic(fmt.Sprintf("presets: parse %s: %v", e.Name(), err))
		}
		if p.ID+".json" != e.Name() {
			panic(fmt.Sprintf("presets: %s has mismatched id %q (file name and id must agree)", e.Name(), p.ID))
		}
		if len(p.Domains) == 0 {
			panic(fmt.Sprintf("presets: %s carries no domains", e.Name()))
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SortOrder < out[j].SortOrder })
	return out
}

// All returns every embedded policy in display order. The slice is shared
// across calls; treat it as read-only.
func All() []Preset {
	return cached
}

// Domains returns the domain list of the policy with the given display name,
// or nil if no policy has that name. Callers that need to mutate the result
// must copy it first.
func Domains(name string) []string {
	for _, p := range cached {
		if p.Name == name {
			return p.Domains
		}
	}
	return nil
}

// NameMap returns every policy as display-name → domains. It rebuilds the map
// on each call so a caller mutating the map cannot corrupt the shared slice.
func NameMap() map[string][]string {
	out := make(map[string][]string, len(cached))
	for _, p := range cached {
		out[p.Name] = p.Domains
	}
	return out
}
