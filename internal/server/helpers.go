// Package server — shared helpers split out of the original monolithic
// handler files. Kept here because they're used by both the JSON API and the
// HTML admin UI.

package server

import (
	"crypto/rand"
	"net/http"
	"time"
)

// handlePing — GET /ping. Cheap liveness check for monitoring.
func (s *Server) handlePing(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"service": "zerolink-backend",
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
}

// handleVersion — GET /version. Returns the build-time version string so
// the Ansible role and clients can detect what's deployed.
func (s *Server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"version": s.Version})
}

// validUsername enforces the username rules used at registration time.
// Lowercase ascii + digits + underscore + hyphen, length 3..32.
func validUsername(u string) bool {
	if len(u) < 3 || len(u) > 32 {
		return false
	}
	for _, r := range u {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '-':
		default:
			return false
		}
	}
	return true
}

// newInviteCode generates one XXXX-XXXX ascii invite code from the unambiguous
// alphabet (no I/L/O/0/1). Used by the admin HTML UI's "create invite" page.
// The JSON API uses storage.MintWithOptions which has its own generator.
func newInviteCode() (string, error) {
	const alphabet = "ABCDEFGHJKMNPQRSTVWXYZ23456789"
	const codeLen = 8
	b := make([]byte, codeLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	final := make([]byte, 9)
	for i := 0; i < codeLen; i++ {
		c := alphabet[int(b[i])%len(alphabet)]
		if i < 4 {
			final[i] = c
		} else {
			final[i+1] = c
		}
	}
	final[4] = '-'
	return string(final), nil
}
