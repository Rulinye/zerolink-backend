// Command zerolink-backend serves the JSON API and admin UI for the
// 0-0link service. See README.md for endpoint details.
//
// Phase 0 carryover: the -version flag prints the build-time version string
// and exits 0. The Ansible role uses this to detect the installed version.
package main

import (
	"context"
	"crypto/tls"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/rulinye/zerolink-backend/internal/auth"
	"github.com/rulinye/zerolink-backend/internal/config"
	"github.com/rulinye/zerolink-backend/internal/cron"
	"github.com/rulinye/zerolink-backend/internal/server"
	"github.com/rulinye/zerolink-backend/internal/storage"
)

// Version is injected at link time via:
//
//	-ldflags="-X main.Version=v1.2.3"
//
// When unset (e.g. `go run`), versionString() falls back to the VCS info
// embedded by the Go toolchain since 1.18, then to "dev".
var Version = ""

//go:embed web/templates/*.html
var templatesFS embed.FS

//go:embed web/static
var staticFS embed.FS

func main() {
	var showVersion bool
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Println(versionString())
		return
	}

	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	logger := newLogger(cfg.LogJSON)
	startAttrs := []any{
		"version", versionString(),
		"listen", cfg.Listen,
		"db", cfg.DBPath,
		"tls_enabled", cfg.TLSEnabled(),
	}
	if cfg.TLSEnabled() {
		startAttrs = append(startAttrs, "tls_listen", cfg.TLSListen)
	}
	logger.Info("starting", startAttrs...)

	db, err := storage.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	signer, err := auth.NewSigner(cfg.JWTSecret, cfg.JWTTTL, cfg.JWTIssuer)
	if err != nil {
		return fmt.Errorf("new signer: %w", err)
	}

	// Sub-FS for templates so handlers reference "login.html", not
	// "web/templates/login.html".
	tplSub, err := fs.Sub(templatesFS, "web/templates")
	if err != nil {
		return err
	}
	tpl, err := server.LoadTemplatesFS(tplSub)
	if err != nil {
		return fmt.Errorf("load templates: %w", err)
	}

	// Same for static.
	staticSub, err := fs.Sub(staticFS, "web/static")
	if err != nil {
		return err
	}

	srv := server.New(cfg, db, signer, logger, tpl, staticSub)
	srv.Version = versionString()

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	srv.RunGC(ctx)
	cron.Run(ctx, db, logger)

	// Plaintext listener — kept on loopback for dev SSH tunnel and for
	// Ansible's post-flight /ping check.
	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// TLS listener — broker reverse-verify and future client direct.
	// Self-signed cert; clients pin the leaf fingerprint, not a CA.
	// Only constructed when both cert and key paths are set; missing
	// files are detected at ListenAndServeTLS time and surfaced via
	// errCh below.
	var httpsSrv *http.Server
	if cfg.TLSEnabled() {
		httpsSrv = &http.Server{
			Addr:              cfg.TLSListen,
			Handler:           srv.Handler(),
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       60 * time.Second,
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		}
	}

	// Buffered to 2 so neither goroutine blocks on send if shutdown wins.
	errCh := make(chan error, 2)

	go func() {
		logger.Info("listening (plaintext)", "addr", cfg.Listen)
		errCh <- httpSrv.ListenAndServe()
	}()

	if httpsSrv != nil {
		go func() {
			logger.Info("listening (TLS)",
				"addr", cfg.TLSListen,
				"cert", cfg.TLSCertPath)
			errCh <- httpsSrv.ListenAndServeTLS(cfg.TLSCertPath, cfg.TLSKeyPath)
		}()
	} else {
		logger.Warn("TLS listener disabled (ZL_TLS_CERT_PATH / ZL_TLS_KEY_PATH not set)")
	}

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("listen: %w", err)
		}
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(
		context.Background(), 15*time.Second)
	defer shutdownCancel()

	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		logger.Warn("plaintext graceful shutdown failed", "err", err)
	}
	if httpsSrv != nil {
		if err := httpsSrv.Shutdown(shutdownCtx); err != nil {
			logger.Warn("TLS graceful shutdown failed", "err", err)
		}
	}
	logger.Info("stopped")
	return nil
}

// newLogger returns a slog.Logger using JSON or text output. JSON in
// production (journald-friendly), text in dev for human reading.
func newLogger(jsonOut bool) *slog.Logger {
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	if jsonOut {
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}

// versionString returns Version if set, otherwise the VCS revision from
// runtime/debug, otherwise "dev". Mirrors Phase 0 main.go.
func versionString() string {
	if Version != "" {
		return Version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" && s.Value != "" {
			rev := s.Value
			if len(rev) > 12 {
				rev = rev[:12]
			}
			return "dev-" + rev
		}
	}
	return "dev"
}
