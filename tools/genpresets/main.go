// genpresets is the one-shot migration generator for the v2.3.0 preset channel:
// it reads the hard-coded preset data out of the matcher package and writes the
// canonical JSON files (presets/<id>.json) plus a golden snapshot the loader
// equivalence test compares against. Run once during the presets.go → JSON
// migration; afterwards the JSON files are the source of truth and this tool
// only regenerates the golden snapshot.
//
//	go run ./tools/genpresets
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"hyperdns/internal/core/matcher"
)

// PresetFile is the on-disk format of one policy in presets/<id>.json.
// It mirrors presets.Preset in the loader; keep the two in sync.
type PresetFile struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Key            string   `json:"key"`
	Category       string   `json:"category"`
	Kind           string   `json:"kind"` // proxy | block | veto
	Icon           string   `json:"icon"`
	Homepage       string   `json:"homepage,omitempty"`
	DefaultEnabled bool     `json:"default_enabled"`
	SortOrder      int      `json:"sort_order"`
	Version        int      `json:"version"`
	UpdatedAt      string   `json:"updated_at"`
	Domains        []string `json:"domains"`
	Notes          string   `json:"notes,omitempty"`
}

// goldenEntry is one row of the equivalence snapshot: exactly what
// GetAllPresets() must keep returning after the migration.
type goldenEntry struct {
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
}

var categories = map[string]string{
	"enable_riot": "gaming", "enable_epic": "gaming", "enable_steam": "gaming",
	"enable_pubg": "gaming", "enable_call_of_duty": "gaming", "enable_supercell": "gaming",
	"enable_ea": "gaming", "enable_blizzard": "gaming", "enable_ubisoft": "gaming",
	"enable_rockstar": "gaming", "enable_roblox": "gaming", "enable_shooters_extra": "gaming",
	"enable_anime_gacha": "gaming", "enable_sports_racing": "gaming", "enable_coop_survival": "gaming",
	"enable_xbox": "platforms", "enable_playstation": "platforms", "enable_platforms_extra": "platforms",
	"enable_discord": "streaming", "enable_twitch": "streaming", "enable_kick": "streaming",
	"enable_spotify": "streaming", "enable_soundcloud": "streaming",
	"enable_google": "services", "enable_ai": "services", "enable_social": "services",
	"enable_dev403":    "tools",
	"enable_downloads": "filters", "enable_adblock": "filters", "enable_familysafe": "filters",
}

var homepages = map[string]string{
	"enable_riot": "https://www.riotgames.com", "enable_epic": "https://www.epicgames.com",
	"enable_steam": "https://store.steampowered.com", "enable_pubg": "https://www.pubg.com",
	"enable_call_of_duty": "https://www.callofduty.com", "enable_supercell": "https://supercell.com",
	"enable_discord": "https://discord.com", "enable_ea": "https://www.ea.com",
	"enable_blizzard": "https://www.blizzard.com", "enable_ubisoft": "https://www.ubisoft.com",
	"enable_rockstar": "https://www.rockstargames.com", "enable_xbox": "https://www.xbox.com",
	"enable_playstation": "https://www.playstation.com", "enable_roblox": "https://www.roblox.com",
	"enable_spotify": "https://www.spotify.com", "enable_soundcloud": "https://soundcloud.com",
	"enable_twitch": "https://www.twitch.tv", "enable_kick": "https://kick.com",
	"enable_google": "https://www.google.com",
}

func main() {
	all := matcher.GetAllPresets()
	catalog := matcher.PolicyCatalog()

	outDir := "presets"
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		panic(err)
	}
	if err := os.MkdirAll(filepath.Join("internal/core/matcher/testdata"), 0o755); err != nil {
		panic(err)
	}

	golden := make([]goldenEntry, 0, len(all))
	totalDomains := 0

	for i, entry := range catalog {
		domains, ok := all[entry.Label]
		if !ok {
			panic("catalog entry missing from GetAllPresets: " + entry.Label)
		}
		id := entry.Key[len("enable_"):]
		kind := "proxy"
		if entry.Blocking {
			kind = "block"
		}
		if entry.Key == "enable_downloads" {
			kind = "veto"
		}
		cat := categories[entry.Key]
		if cat == "" {
			panic("no category for " + entry.Key)
		}
		pf := PresetFile{
			ID:             id,
			Name:           entry.Label,
			Key:            entry.Key,
			Category:       cat,
			Kind:           kind,
			Icon:           "icons/" + id + ".svg",
			Homepage:       homepages[entry.Key],
			DefaultEnabled: matcher.DefaultRuleEnabled(entry.Key),
			SortOrder:      i,
			Version:        1,
			UpdatedAt:      "2026-09-23T00:00:00Z",
			Domains:        domains,
		}
		data, err := json.MarshalIndent(pf, "", "  ")
		if err != nil {
			panic(err)
		}
		path := filepath.Join(outDir, id+".json")
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			panic(err)
		}
		fmt.Printf("wrote %s (%d domains, %s)\n", path, len(domains), kind)
		totalDomains += len(domains)
	}

	// Golden snapshot: the exact (name, domains) pairs of today's GetAllPresets,
	// name-sorted so the test does not depend on Go map iteration order.
	names := make([]string, 0, len(all))
	for name := range all {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		golden = append(golden, goldenEntry{Name: name, Domains: all[name]})
	}
	gdata, err := json.MarshalIndent(golden, "", "  ")
	if err != nil {
		panic(err)
	}
	gpath := "internal/core/matcher/testdata/presets_golden.json"
	if err := os.WriteFile(gpath, append(gdata, '\n'), 0o644); err != nil {
		panic(err)
	}
	fmt.Printf("golden snapshot: %s (%d presets, %d domains)\n", gpath, len(golden), totalDomains)
}
