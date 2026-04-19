// Package server wires together storage, auth, and HTTP handlers.
//
// Routing layout per phase-1-handover §3.8:
//
//	/ping                       (no auth)
//	/version                    (no auth)
//	/sub/{token}                (no auth, token IS the credential)
//	/api/v1/auth/register       (no auth, but invite required)
//	/api/v1/auth/login          (no auth)
//	/api/v1/auth/me             (jwt)
//	/api/v1/auth/logout         (jwt)
//	/api/v1/nodes               (jwt)
//	/api/v1/subscriptions       (jwt)
//	/api/v1/admin/*             (jwt + is_admin)
//	/admin                      (cookie session, served from /web)
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/rulinye/zerolink-backend/internal/auth"
	"github.com/rulinye/zerolink-backend/internal/config"
	"github.com/rulinye/zerolink-backend/internal/storage"
)

// Server is the assembled HTTP application. Construct with New, mount the
// router into your http.Server.
type Server struct {
	cfg      *config.Config
	db       *storage.DB
	signer   *auth.Signer
	log      *slog.Logger
	tpl      *template.Template
	staticFS fs.FS

	router chi.Router

	// Version is injected from main via SetVersion so /version matches the
	// build-time string (parity with Phase 0 behavior).
	Version string
}

// New builds a Server from its dependencies. Call Routes() afterwards to get
// the http.Handler to mount.
func New(cfg *config.Config, db *storage.DB, signer *auth.Signer, log *slog.Logger,
	tpl *template.Template, staticFS fs.FS) *Server {
	s := &Server{
		cfg:      cfg,
		db:       db,
		signer:   signer,
		log:      log,
		tpl:      tpl,
		staticFS: staticFS,
		Version:  "dev",
	}
	s.router = s.buildRouter()
	return s
}

// Handler returns the chi router as http.Handler.
func (s *Server) Handler() http.Handler { return s.router }

// requestLogger emits a structured slog line per request. Mirrors the Phase 0
// pattern from the existing main.go middleware.
func (s *Server) requestLogger() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)
			s.log.Info("http",
				"method", r.Method,
				"path", r.URL.Path,
				"status", ww.Status(),
				"bytes", ww.BytesWritten(),
				"dur_ms", time.Since(start).Milliseconds(),
				"req_id", middleware.GetReqID(r.Context()),
			)
		})
	}
}

// --- tiny helpers used by handlers in sibling files ---

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func decodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	return nil
}

// runGC starts a goroutine that periodically prunes the revoked-tokens table.
// Cancel via the returned ctx parent. Caller is the main package.
func (s *Server) RunGC(ctx context.Context) {
	go func() {
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				n, err := s.db.Tokens.GCExpired(ctx)
				if err != nil {
					s.log.Warn("revoked tokens GC failed", "err", err)
					continue
				}
				s.log.Info("revoked tokens GC", "deleted", n)
			}
		}
	}()
}
