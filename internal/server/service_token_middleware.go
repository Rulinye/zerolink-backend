// server/service_token_middleware.go — Batch 3.3 Group 1c.
//
// Service token middleware authenticates internal-service callers (currently:
// broker daemons) by Bearer token. Used only for the /api/v1/auth/verify
// endpoint where brokers reverse-validate client JWTs.
//
// Note: this middleware is intentionally separate from the JWT-based user
// auth middleware (internal/auth.Middleware). The two authentication paths
// are non-overlapping by design — service tokens identify SERVICES, not
// USERS, and they live in a different table with different rotation
// semantics. Keeping them separate avoids accidental cross-contamination
// (e.g. a broker's service token shouldn't accidentally satisfy a user
// route).

package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/rulinye/zerolink-backend/internal/storage"
)

// serviceTokenCtxKey is the context key under which the resolved
// *storage.ServiceToken is stored. Handlers can pull this out for logging
// (e.g. "verified by broker-kr") but most don't need to.
type serviceTokenCtxKey struct{}

// serviceTokenFromContext returns the resolved *storage.ServiceToken if the
// request was authenticated by serviceTokenMiddleware. Returns nil
// otherwise.
func serviceTokenFromContext(ctx context.Context) *storage.ServiceToken {
	v, _ := ctx.Value(serviceTokenCtxKey{}).(*storage.ServiceToken)
	return v
}

// serviceTokenMiddleware enforces a valid `Authorization: Bearer <token>`
// header where <token> matches an active row in service_tokens. On success
// it stores the resolved *storage.ServiceToken in the request context and
// fires a best-effort TouchLastUsed update so admin tooling can surface
// "is broker-X alive" without polling.
//
// Failure modes (all return 401, body intentionally minimal — never
// distinguishes "missing header" from "bad token" from "disabled" to avoid
// leaking label existence to attackers):
//   - missing or malformed Authorization header
//   - token doesn't match any row
//   - token row exists but disabled=1
//   - DB error during lookup (logged, surfaced as 401 to caller; admins
//     check journald)
func (s *Server) serviceTokenMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(raw, prefix) {
			writeError(w, http.StatusUnauthorized, "service token required")
			return
		}
		plaintext := strings.TrimSpace(raw[len(prefix):])
		if plaintext == "" {
			writeError(w, http.StatusUnauthorized, "service token required")
			return
		}

		tok, err := s.db.ServiceTokens.Verify(r.Context(), plaintext)
		if err != nil {
			if errors.Is(err, storage.ErrServiceTokenInvalid) {
				writeError(w, http.StatusUnauthorized, "service token invalid")
				return
			}
			s.log.Warn("service token verify failed", "err", err)
			writeError(w, http.StatusUnauthorized, "service token invalid")
			return
		}

		// Best-effort: fire-and-forget touch so the request path doesn't
		// pay for a write. context.Background() so the update isn't
		// canceled when the response flushes.
		go func(id int64) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := s.db.ServiceTokens.TouchLastUsed(ctx, id); err != nil {
				s.log.Warn("service token TouchLastUsed failed",
					"label", tok.Label, "err", err)
			}
		}(tok.ID)

		ctx := context.WithValue(r.Context(), serviceTokenCtxKey{}, tok)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
