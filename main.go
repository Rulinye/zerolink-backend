// Command zerolink-backend is the control plane for 0-0link.
//
// Phase 0: serves a single GET /ping endpoint to validate the deployment
// pipeline. Real auth, node management, and traffic accounting are added
// in phase 1.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Version is overridden at build time via -ldflags "-X main.Version=...".
// When building from source without ldflags, we fall back to VCS info from debug.ReadBuildInfo().
var Version = "dev"

func main() {
	var (
		listen      = flag.String("listen", "127.0.0.1:8080", "address to listen on (host:port)")
		logJSON     = flag.Bool("log-json", false, "emit logs as JSON (default: human-readable)")
		showVersion = flag.Bool("version", false, "print version and exit (used by ansible for upgrade detection)")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(versionString())
		return
	}

	// Logger setup. JSON in production (systemd/journal will index it),
	// text in dev.
	var handler slog.Handler
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	if *logJSON {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}
	logger := slog.New(handler).With("service", "zerolink-backend", "version", versionString())
	slog.SetDefault(logger)

	logger.Info("starting", "listen", *listen)

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(requestLogger(logger))

	r.Get("/ping", handlePing)
	r.Get("/version", handleVersion)

	srv := &http.Server{
		Addr:              *listen,
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		logger.Error("listen failed", "err", err)
		os.Exit(1)
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "err", err)
		os.Exit(1)
	}
	logger.Info("stopped cleanly")
}

// handlePing returns a static OK payload. Used by humans (curl), Ansible
// post-deploy verification, and any future health checker.
func handlePing(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"service": "zerolink-backend",
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
}

// handleVersion returns build/version metadata. Useful for verifying that
// the deployed binary matches the expected commit.
func handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version": versionString(),
	})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		// Client probably disconnected — nothing useful we can do.
		slog.Default().Warn("write json failed", "err", err)
	}
}

// requestLogger logs each request's method, path, status, and duration
// using slog. We don't use chi's built-in middleware.Logger because it
// writes to log.Default() instead of slog.
func requestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)
			logger.Info("http",
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

func versionString() string {
	if Version != "dev" {
		return Version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		var rev, modified string
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				rev = s.Value
				if len(rev) > 7 {
					rev = rev[:7]
				}
			case "vcs.modified":
				if s.Value == "true" {
					modified = "+dirty"
				}
			}
		}
		if rev != "" {
			return fmt.Sprintf("dev-%s%s", rev, modified)
		}
	}
	return Version
}
