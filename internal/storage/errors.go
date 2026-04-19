package storage

import (
	"errors"
	"strings"
)

// ErrNotFound is returned by repo Get/GetBy* methods when the row is missing.
// Repo callers should errors.Is(err, ErrNotFound) rather than checking for
// sql.ErrNoRows directly.
var ErrNotFound = errors.New("storage: not found")

// scanner is satisfied by both *sql.Row and *sql.Rows so scan helpers can
// accept either.
type scanner interface{ Scan(dest ...any) error }

// isUniqueErr returns true if err looks like a SQLite UNIQUE constraint
// violation. modernc.org/sqlite formats these as "constraint failed: UNIQUE
// constraint failed: <table>.<column> (1555)" or similar; the "UNIQUE
// constraint failed" substring is stable across versions.
func isUniqueErr(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}
