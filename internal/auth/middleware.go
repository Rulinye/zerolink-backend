package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/rulinye/zerolink-backend/internal/storage"
)

type contextKey string

const claimsKey contextKey = "auth.claims"

// FromContext returns the Claims set by Middleware. Returns nil if the request
// did not pass through the middleware (i.e., on an unauthenticated route).
func FromContext(ctx context.Context) *Claims {
	c, _ := ctx.Value(claimsKey).(*Claims)
	return c
}

// Middleware verifies the Authorization: Bearer <jwt> header, checks the token
// against the revocation list, loads the user, and rejects if the user is
// disabled. On success it injects the Claims into the request context.
//
// The user repo is passed in (rather than the whole storage.DB) so test code
// can plug in a fake.
func Middleware(s *Signer, users *storage.UserRepo, revoked *storage.RevokedTokenRepo) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok := bearerToken(r)
			if tok == "" {
				writeErr(w, http.StatusUnauthorized, "missing bearer token")
				return
			}
			claims, err := s.Parse(tok)
			if err != nil {
				writeErr(w, http.StatusUnauthorized, "invalid token: "+err.Error())
				return
			}

			isRev, err := revoked.IsRevoked(r.Context(), claims.ID)
			if err != nil {
				writeErr(w, http.StatusInternalServerError, "revocation check failed")
				return
			}
			if isRev {
				writeErr(w, http.StatusUnauthorized, "token revoked")
				return
			}

			u, err := users.GetByID(r.Context(), claims.UserID)
			if err != nil {
				if errors.Is(err, storage.ErrNotFound) {
					writeErr(w, http.StatusUnauthorized, "user no longer exists")
					return
				}
				writeErr(w, http.StatusInternalServerError, "user lookup failed")
				return
			}
			if u.IsDisabled {
				writeErr(w, http.StatusForbidden, "account disabled")
				return
			}

			ctx := context.WithValue(r.Context(), claimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// AdminOnly is a downstream middleware that 403s requests whose claims do not
// have the admin bit. Must be used AFTER Middleware.
func AdminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := FromContext(r.Context())
		if c == nil {
			writeErr(w, http.StatusUnauthorized, "no auth context")
			return
		}
		if !c.IsAdmin {
			writeErr(w, http.StatusForbidden, "admin only")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if !strings.HasPrefix(h, p) {
		return ""
	}
	return strings.TrimSpace(h[len(p):])
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
