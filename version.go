// Package hyperdns is the module root package. Its sole purpose is to embed
// version.json (the single source of truth for the build version) into the
// binary so every surface (API, Web UI, TUI, CLI) reports the same values.
package hyperdns

import _ "embed"

// EmbeddedVersionJSON holds the raw bytes of version.json at build time.
// Edit version.json to change the application version — nothing else.
//
//go:embed version.json
var EmbeddedVersionJSON []byte
