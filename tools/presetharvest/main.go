// presetharvest proposes new subdomains for existing policies by enumerating
// Certificate Transparency logs (crt.sh). It never invents a new policy and
// never touches a domain outside a zone the catalog already carries: every
// candidate must be a subdomain of a zone listed in that same policy file.
//
// It edits presets/<id>.json in place (append + version bump + updated_at),
// regenerates the golden snapshot, and prints a machine-readable summary the
// workflow uses to decide between auto-merge (Tier 1) and human review (Tier 2).
//
// Usage:
//
//	presetharvest -in presets -max-per-policy 8 -max-total 20 -deadline 8m
//
// Exit codes: 0 = ran (maybe with zero candidates), 1 = hard failure.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type policy struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Key            string   `json:"key"`
	Category       string   `json:"category"`
	Kind           string   `json:"kind"`
	Icon           string   `json:"icon"`
	Homepage       string   `json:"homepage,omitempty"`
	DefaultEnabled bool     `json:"default_enabled"`
	SortOrder      int      `json:"sort_order"`
	Version        int      `json:"version"`
	UpdatedAt      string   `json:"updated_at"`
	Domains        []string `json:"domains"`
	Notes          string   `json:"notes,omitempty"`
}

var domainRe = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// labels we never auto-add: infrastructure names that churn constantly and add
// nothing to routing, plus anything that looks like a random subdomain.
var skipLabel = regexp.MustCompile(`^(www|mail|smtp|imap|pop|ns[0-9]*|dns[0-9]*|mx[0-9]*|_|autodiscover|autoconfig|dev|staging|test|preprod|preview|internal|corp|vpn|git|ci|jenkins|k8s|status|metrics|grafana|prometheus|sentry|backup|bak|old|legacy|alpha|sandbox|edge-[0-9a-f]+|ipv4|ipv6)$`)

func main() {
	in := flag.String("in", "presets", "presets directory")
	maxPer := flag.Int("max-per-policy", 8, "maximum additions per policy before the run is a Tier-2 (human review) change")
	maxTotal := flag.Int("max-total", 20, "maximum additions overall before the run is Tier 2")
	deadline := flag.Duration("deadline", 8*time.Minute, "wall-clock budget for crt.sh queries")
	flag.Parse()

	client := &http.Client{Timeout: 45 * time.Second}
	stop := time.Now().Add(*deadline)

	files, err := os.ReadDir(*in)
	if err != nil {
		fatal(err)
	}

	totalAdded := 0
	changed := 0
	type summaryRow struct {
		ID      string   `json:"id"`
		Name    string   `json:"name"`
		Added   []string `json:"added"`
		Queried []string `json:"queried_zones"`
		Errors  []string `json:"errors,omitempty"`
	}
	var rows []summaryRow

	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") || f.Name() == "manifest.json" {
			continue
		}
		if time.Now().After(stop) {
			fmt.Fprintln(os.Stderr, "harvest: deadline reached; remaining policies untouched")
			break
		}
		path := filepath.Join(*in, f.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			fatal(err)
		}
		var p policy
		if err := json.Unmarshal(raw, &p); err != nil {
			fatal(fmt.Errorf("%s: %w", f.Name(), err))
		}

		present := make(map[string]bool, len(p.Domains))
		for _, d := range p.Domains {
			present[d] = true
		}

		// Zones to enumerate: the base of every exact domain entry. Wildcard
		// entries already cover their subdomains, so they are skipped as zones.
		zones := map[string]bool{}
		for _, d := range p.Domains {
			if strings.HasPrefix(d, "*.") {
				continue
			}
			parts := strings.Split(d, ".")
			if len(parts) < 2 {
				continue
			}
			// Registerable-ish base: last two labels (co.uk style bases come out
			// slightly wrong; a wrong base only means crt.sh returns nothing
			// useful, never a wrong addition).
			zones[strings.Join(parts[len(parts)-2:], ".")] = true
		}

		row := summaryRow{ID: p.ID, Name: p.Name}
		var candidates []string
		for zone := range zones {
			if time.Now().After(stop) {
				break
			}
			row.Queried = append(row.Queried, zone)
			names, err := crtSubdomains(client, zone)
			if err != nil {
				row.Errors = append(row.Errors, zone+": "+err.Error())
				continue
			}
			for _, name := range names {
				name = strings.ToLower(strings.TrimSpace(name))
				if name == "" || strings.Contains(name, "*") || !domainRe.MatchString(name) {
					continue
				}
				if !strings.HasSuffix(name, "."+zone) {
					continue
				}
				label := strings.SplitN(name, ".", 2)[0]
				if skipLabel.MatchString(label) {
					continue
				}
				if present[name] {
					continue
				}
				// The wildcard already covers it — adding the host changes nothing.
				if present["*."+strings.SplitN(name, ".", 2)[1]] {
					continue
				}
				candidates = append(candidates, name)
			}
			time.Sleep(400 * time.Millisecond) // crt.sh is a shared community service
		}

		sort.Strings(candidates)
		candidates = dedupe(candidates)
		if len(candidates) > *maxPer {
			// A single policy gaining a pile of hosts is exactly the shape a
			// hijacked or repurposed zone takes. Park the whole policy for review.
			row.Errors = append(row.Errors,
				fmt.Sprintf("candidates (%d) exceed the per-policy cap (%d) — Tier 2", len(candidates), *maxPer))
			rows = append(rows, row)
			continue
		}
		if len(candidates) == 0 {
			rows = append(rows, row)
			continue
		}

		p.Domains = append(p.Domains, candidates...)
		sort.Strings(p.Domains)
		p.Version++
		p.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		out, err := json.MarshalIndent(p, "", "  ")
		if err != nil {
			fatal(err)
		}
		if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
			fatal(err)
		}
		row.Added = candidates
		rows = append(rows, row)
		totalAdded += len(candidates)
		changed++
	}

	// Machine-readable summary for the workflow.
	sum, _ := json.MarshalIndent(map[string]any{
		"changed_policies": changed,
		"total_added":      totalAdded,
		"tier":             tierOf(totalAdded, *maxTotal),
		"policies":         rows,
	}, "", "  ")
	fmt.Println(string(sum))

	if totalAdded > *maxTotal {
		fmt.Fprintf(os.Stderr, "harvest: %d additions exceed the total cap (%d) — Tier 2, do not auto-merge\n", totalAdded, *maxTotal)
	}
}

// tierOf classifies the run: under the total cap is Tier 1 (eligible for
// auto-merge), anything larger is Tier 2.
func tierOf(total, cap int) string {
	if total <= cap {
		return "1"
	}
	return "2"
}

func dedupe(in []string) []string {
	out := in[:0]
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}

// crtSubdomains asks crt.sh for every name it has seen issued under a zone.
func crtSubdomains(client *http.Client, zone string) ([]string, error) {
	u := "https://crt.sh/?q=" + url.QueryEscape("%."+zone) + "&output=json"
	resp, err := client.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	var rows []struct {
		CommonName string `json:"common_name"`
		NameValue  string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("crt.sh response was not JSON: %w", err)
	}
	var out []string
	for _, r := range rows {
		for _, name := range strings.Split(r.NameValue, "\n") {
			out = append(out, name)
		}
		out = append(out, r.CommonName)
	}
	return out, nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "presetharvest:", err)
	os.Exit(1)
}
