// Package auth — JWT middleware.
//
// Batch 3a rewrites the middleware to do three extra checks beyond signature
// verification (was Phase 1's baseline):
//
//   1. Fetch the user fresh from DB and bail if IsEffectivelyDisabled(now).
//      This makes admin "disable" take effect on the next API call
//      (typically within 30s heartbeat) without any token revocation dance.
//
//   2. Compare the JWT's `iat` claim against users.password_changed_at. Any
//      token issued before that timestamp is considered implicitly revoked.
//      This mechanism covers:
//        - login (F15 "kick previous sessions"): login bumps password_changed_at
//        - change-password (F17)
//        - admin "disable" (via RevokeAllForUser in the disable handler)
//
//   3. Check the jti against the revoked_tokens table (legacy explicit revoke,
//      e.g. for /auth/logout on a single device).
//
// On any failure we return 401 with a hint; the client treats this as a hard
// kickout (D2.24).

package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/rulinye/zerolink-backend/internal/storage"
)

type contextKey string

const claimsCtxKey contextKey = "zl-auth-claims"

// Context payload available to downstream handlers via auth.FromContext.
type Context struct {
	UserID   int64
	Username string
	IsAdmin  bool
	JTI      string
	IssuedAt time.Time
}

// FromContext returns the auth context populated by Middleware.
// Panics if the route wasn't wrapped by Middleware — that's a bug, not a
// runtime-handleable error.
func FromContext(ctx context.Context) *Context {
	v, ok := ctx.Value(claimsCtxKey).(*Context)
	if !ok {
		panic("auth.FromContext called outside authenticated route")
	}
	return v
}

// Middleware returns an http middleware that enforces a valid, non-revoked,
// non-disabled user on the request.
func Middleware(signer *Signer, users *storage.UserRepo, tokens *storage.RevokedTokenRepo) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok, ok := bearerToken(r)
			if !ok {
				writeAuthError(w, http.StatusUnauthorized, "missing bearer token")
				return
			}
			claims, err := signer.Parse(tok)
			if err != nil {
				writeAuthError(w, http.StatusUnauthorized, "invalid token: "+err.Error())
				return
			}

			ctx := r.Context()

			// Check 1: revocation list.
			revoked, err := tokens.IsRevoked(ctx, claims.ID)
			if err != nil {
				writeAuthError(w, http.StatusInternalServerError, "revocation check failed")
				return
			}
			if revoked {
				writeAuthError(w, http.StatusUnauthorized, "token revoked")
				return
			}

			// Check 2 + 3: user state.
			user, err := users.GetByID(ctx, claims.UserID)
			if err != nil {
				if errors.Is(err, storage.ErrNotFound) {
					// User was deleted — treat any outstanding token as invalid.
					writeAuthError(w, http.StatusUnauthorized, "user no longer exists")
					return
				}
				writeAuthError(w, http.StatusInternalServerError, "user lookup failed")
				return
			}
			if user.IsEffectivelyDisabled(time.Now()) {
				writeAuthError(w, http.StatusForbidden, "account disabled")
				return
			}
			if user.PasswordChangedAt != nil && claims.IssuedAt != nil {
				iat := claims.IssuedAt.Time
				// Tokens issued strictly before the last password_changed bump
				// are stale (covers login, change-pw, admin-disable flows).
				// Use 1-second tolerance — SQLite CURRENT_TIMESTAMP is second
				// precision, JWT iat is also seconds; allow equal.
				if iat.Before(user.PasswordChangedAt.Add(-1 * time.Second)) {
					writeAuthError(w, http.StatusUnauthorized, "token superseded")
					return
				}
			}

			// All good — attach context and continue.
			authCtx := &Context{
				UserID:   claims.UserID,
				Username: claims.Username,
				IsAdmin:  claims.IsAdmin,
				JTI:      claims.ID,
			}
			if claims.IssuedAt != nil {
				authCtx.IssuedAt = claims.IssuedAt.Time
			}
			r2 := r.WithContext(context.WithValue(ctx, claimsCtxKey, authCtx))
			next.ServeHTTP(w, r2)
		})
	}
}

// AdminOnly must come AFTER Middleware. Returns 403 if the authed user is
// not an admin.
func AdminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := FromContext(r.Context())
		if !c.IsAdmin {
			writeAuthError(w, http.StatusForbidden, "admin privileges required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// bearerToken extracts the token from "Authorization: Bearer <token>".
func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", false
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return "", false
	}
	tok := strings.TrimSpace(h[len(prefix):])
	return tok, tok != ""
}

// writeAuthError emits a JSON {"error": msg} response.
func writeAuthError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":` + jsonQuote(msg) + `}`))
}

// jsonQuote quotes a string as a JSON literal. Avoids pulling in encoding/json
// for this hot path.
func jsonQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				continue
			}
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
