// Package version provides a single, embedded source of truth for the
// application version. version.json at the repository root is embedded into
// the binary at compile time; a short content hash (fingerprint) is derived
// from it so API, Web UI, TUI and CLI are guaranteed to stay in sync — they
// all read the exact same in-memory struct.
package version

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"runtime"
	"sync"

	hdns "hyperdns"
)

// Commit may be overridden at build time via:
//
//	go build -ldflags "-X hyperdns/internal/version.Commit=$(git rev-parse --short HEAD)"
var Commit string

// Info is the version payload shared by every surface of the application.
type Info struct {
	Version  string `json:"version"`
	Channel  string `json:"channel"`
	Codename string `json:"codename,omitempty"`
	Display  string `json:"display"` // e.g. "v1.4.0-beta"
	Hash     string `json:"hash"`    // content fingerprint of version.json
	Commit   string `json:"commit,omitempty"`
	Go       string `json:"go"`
}

var (
	once    sync.Once
	loaded  Info
	loadErr error
)

// load parses the embedded version.json exactly once.
func load() (Info, error) {
	once.Do(func() {
		var raw struct {
			Version  string `json:"version"`
			Channel  string `json:"channel"`
			Codename string `json:"codename"`
			Homepage string `json:"homepage"`
		}
		if err := json.Unmarshal(hdns.EmbeddedVersionJSON, &raw); err != nil {
			loadErr = fmt.Errorf("invalid embedded version.json: %w", err)
			return
		}
		if raw.Version == "" {
			loadErr = fmt.Errorf("embedded version.json missing \"version\" field")
			return
		}

		// Content fingerprint: hash the *semantic* fields (not the raw bytes),
		// so re-formatting the file does not change the hash, while any real
		// version bump does. 8 hex chars are plenty for a sync indicator.
		canonical, _ := json.Marshal(map[string]string{
			"version":  raw.Version,
			"channel":  raw.Channel,
			"codename": raw.Codename,
		})
		sum := sha256.Sum256(canonical)
		hash := hex.EncodeToString(sum[:])[:8]

		display := "v" + raw.Version
		if raw.Channel != "" {
			display += "-" + raw.Channel
		}

		loaded = Info{
			Version:  raw.Version,
			Channel:  raw.Channel,
			Codename: raw.Codename,
			Display:  display,
			Hash:     hash,
			Commit:   Commit,
			Go:       runtime.Version(),
		}
	})
	return loaded, loadErr
}

// Get returns the parsed version info.
func Get() Info {
	info, _ := load()
	return info
}

// Display returns "v1.4.0-beta".
func Display() string {
	if info, err := load(); err == nil {
		return info.Display
	}
	return "v0.0.0-unknown"
}

// Short returns "v1.4.0-beta (hash:123456ab)" — the format used in logs,
// banners and the TUI.
func Short() string {
	info, err := load()
	if err != nil {
		return "v0.0.0-unknown"
	}
	s := fmt.Sprintf("%s (hash:%s)", info.Display, info.Hash)
	if info.Commit != "" {
		s += fmt.Sprintf(" (commit:%s)", info.Commit)
	}
	return s
}

// DriftError is returned when a version.json found on disk does not match the
// binary's embedded copy (stale binary or mixed deployment).
type DriftError struct {
	DiskVersion     string
	EmbeddedVersion string
}

func (e *DriftError) Error() string {
	return fmt.Sprintf(
		"version drift detected: version.json on disk reports %s but this binary was built with %s — replace the binary or the file so they match",
		e.DiskVersion, e.EmbeddedVersion)
}

// CheckDiskFile compares a version.json found next to the binary / in the
// working directory against the embedded one, detecting stale deployments.
func CheckDiskFile(data []byte) error {
	info, err := load()
	if err != nil {
		return err
	}
	var disk Info
	if err := json.Unmarshal(data, &disk); err != nil {
		return fmt.Errorf("version.json on disk is not valid JSON: %w", err)
	}
	if disk.Version != "" && disk.Version != info.Version {
		return &DriftError{DiskVersion: disk.Version, EmbeddedVersion: info.Version}
	}
	return nil
}
