package storage

import "strings"

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
