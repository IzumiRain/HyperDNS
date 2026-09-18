package version

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestVersionLoadedFromEmbeddedJSON(t *testing.T) {
	info, err := load()
	if err != nil {
		t.Fatalf("failed to load embedded version.json: %v", err)
	}
	if info.Version == "" {
		t.Fatal("expected non-empty version")
	}
	if !strings.HasPrefix(info.Display, "v") {
		t.Fatalf("expected display to start with 'v', got %q", info.Display)
	}
	if len(info.Hash) != 8 {
		t.Fatalf("expected 8-char hash, got %q", info.Hash)
	}
	if info.Go == "" {
		t.Fatal("expected Go runtime version to be filled")
	}
}

func TestHashIsStableAndSemantic(t *testing.T) {
	a := Get()
	b := Get()
	if a.Hash != b.Hash {
		t.Fatalf("hash not stable: %s vs %s", a.Hash, b.Hash)
	}
	// Hash must derive from semantic content: simulate a bump and verify drift detection
	bump := []byte(`{"version":"9.9.9","channel":"beta"}`)
	if err := CheckDiskFile(bump); err == nil {
		t.Fatal("expected drift error for mismatched disk version")
	} else {
		if _, ok := err.(*DriftError); !ok {
			t.Fatalf("expected *DriftError, got %T", err)
		}
	}
	// Same version on disk (formatted differently) must NOT drift
	same := []byte("{\n  \"version\": \"" + a.Version + "\",\n  \"channel\": \"" + a.Channel + "\"\n}\n")
	if err := CheckDiskFile(same); err != nil {
		t.Fatalf("expected no drift for same version, got: %v", err)
	}
}

func TestJSONShape(t *testing.T) {
	data, _ := json.Marshal(Get())
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Info must be JSON marshalable: %v", err)
	}
	for _, key := range []string{"version", "channel", "display", "hash", "go"} {
		if _, ok := m[key]; !ok {
			t.Fatalf("expected key %q in version JSON", key)
		}
	}
}
