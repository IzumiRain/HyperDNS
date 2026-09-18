package bootstrap

import (
	"errors"
	"fmt"
	"os"
)

// PathsState describes which members of the database/master-key pair exist.
type PathsState uint8

const (
	PathsFresh PathsState = iota
	PathsComplete
	PathsIncomplete
)

var (
	ErrMissingMasterKey = errors.New("data.db exists but master.key is missing; restore the original master.key")
	ErrMissingDatabase  = errors.New("master.key exists but data.db is missing; restore the matching database")
)

// ClassifyPaths inspects the database/master-key pair without creating or
// changing either path.
func ClassifyPaths(dbPath, keyPath string) (PathsState, error) {
	dbExists, err := pathExists(dbPath)
	if err != nil {
		return PathsIncomplete, fmt.Errorf("inspect database path %q: %w", dbPath, err)
	}
	keyExists, err := pathExists(keyPath)
	if err != nil {
		return PathsIncomplete, fmt.Errorf("inspect master-key path %q: %w", keyPath, err)
	}

	switch {
	case dbExists && keyExists:
		return PathsComplete, nil
	case dbExists:
		return PathsIncomplete, ErrMissingMasterKey
	case keyExists:
		return PathsIncomplete, ErrMissingDatabase
	default:
		return PathsFresh, nil
	}
}

func pathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}
