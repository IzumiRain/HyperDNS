package bootstrap_test

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"hyperdns/internal/bootstrap"
)

func TestClassifyPaths(t *testing.T) {
	tests := []struct {
		name      string
		database  bool
		key       bool
		wantState bootstrap.PathsState
		wantErr   error
	}{
		{name: "fresh", wantState: bootstrap.PathsFresh},
		{name: "complete", database: true, key: true, wantState: bootstrap.PathsComplete},
		{name: "database without key", database: true, wantState: bootstrap.PathsIncomplete, wantErr: bootstrap.ErrMissingMasterKey},
		{name: "key without database", key: true, wantState: bootstrap.PathsIncomplete, wantErr: bootstrap.ErrMissingDatabase},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			dbPath := filepath.Join(dir, "data.db")
			keyPath := filepath.Join(dir, "master.key")
			if tt.database {
				mustWriteFixture(t, dbPath, []byte("database-fixture"))
			}
			if tt.key {
				mustWriteFixture(t, keyPath, []byte("master-key-fixture"))
			}

			before := snapshotDirectory(t, dir)
			gotState, err := bootstrap.ClassifyPaths(dbPath, keyPath)
			if gotState != tt.wantState {
				t.Errorf("state = %v, want %v", gotState, tt.wantState)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want %v", err, tt.wantErr)
			}
			after := snapshotDirectory(t, dir)
			if !reflect.DeepEqual(after, before) {
				t.Fatalf("classification changed fixtures or directory entries:\nbefore: %#v\nafter:  %#v", before, after)
			}
		})
	}
}

type directorySnapshot struct {
	Names []string
	Files map[string][]byte
}

func snapshotDirectory(t *testing.T, dir string) directorySnapshot {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	got := directorySnapshot{Files: make(map[string][]byte)}
	for _, entry := range entries {
		got.Names = append(got.Names, entry.Name())
		if entry.Type().IsRegular() {
			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				t.Fatalf("ReadFile(%s): %v", entry.Name(), err)
			}
			got.Files[entry.Name()] = data
		}
	}
	sort.Strings(got.Names)
	return got
}

func mustWriteFixture(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}
