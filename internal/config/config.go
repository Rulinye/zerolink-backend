// Package config reads runtime configuration from environment variables
// (with flag overrides for the small set of options used in development).
//
// Per phase-1-handover §5: no viper, no spf13. Stdlib + a few helpers.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config is the fully-resolved runtime configuration.
type Config struct {
	// Listen is the HTTP plaintext listen address, e.g. "127.0.0.1:8080".
	// Kept for the dev SSH-tunnel workflow and for Ansible's loopback
	// post-flight /ping check. Public-facing API access goes through the
	// TLS listener (TLSListen) when configured.
	Listen string

	// DBPath is the SQLite file path.
	DBPath string

	// JWTSecret is the HS256 secret. Must be >=32 bytes.
	JWTSecret []byte

	// JWTTTL is the access-token lifetime.
	JWTTTL time.Duration

	// JWTIssuer is the iss claim. Defaults to "zerolink-backend".
	JWTIssuer string

	// AdminUIEnabled toggles the /admin HTML routes. Default true.
	AdminUIEnabled bool

	// LogJSON makes slog emit JSON instead of text. Default true (production).
	LogJSON bool

	// ----- Batch 3.3 Group 1b: TLS listener -----
	//
	// When TLSCertPath and TLSKeyPath are both set, an additional HTTPS
	// listener runs on TLSListen alongside the plaintext Listen address.
	// The cert is self-signed; verification on the client side (broker
	// reqwest) happens via leaf certificate sha256 fingerprint pinning,
	// not CA chain validation. See 0-0link-infra/roles/backend for the
	// generation task and fingerprint propagation.
	//
	// Both paths must be supplied together (or both omitted). Mixing one
	// with the other returns a config error at startup.

	// TLSListen is the TLS listen address, default "0.0.0.0:8443".
	TLSListen string

	// TLSCertPath is the path to a PEM-encoded TLS certificate. Empty
	// disables the TLS listener entirely.
	TLSCertPath string

	// TLSKeyPath is the path to a PEM-encoded TLS private key. Empty
	// disables the TLS listener entirely.
	TLSKeyPath string
}

// TLSEnabled reports whether the TLS listener should be started.
func (c *Config) TLSEnabled() bool {
	return c.TLSCertPath != "" && c.TLSKeyPath != ""
}

// Load reads configuration from env vars and applies defaults. Returns an
// error for any field that is required but missing or invalid.
func Load() (*Config, error) {
	c := &Config{
		Listen:         envOr("ZL_LISTEN", "127.0.0.1:8080"),
		DBPath:         envOr("ZL_DB_PATH", "/var/lib/zerolink-backend/zerolink.db"),
		JWTIssuer:      envOr("ZL_JWT_ISSUER", "zerolink-backend"),
		AdminUIEnabled: envBool("ZL_ADMIN_UI", true),
		LogJSON:        envBool("ZL_LOG_JSON", true),

		TLSListen:   envOr("ZL_TLS_LISTEN", "0.0.0.0:8443"),
		TLSCertPath: os.Getenv("ZL_TLS_CERT_PATH"),
		TLSKeyPath:  os.Getenv("ZL_TLS_KEY_PATH"),
	}

	secret := os.Getenv("ZL_JWT_SECRET")
	if secret == "" {
		return nil, errors.New("config: ZL_JWT_SECRET must be set (>=32 bytes)")
	}
	c.JWTSecret = []byte(secret)
	if len(c.JWTSecret) < 32 {
		return nil, fmt.Errorf("config: ZL_JWT_SECRET too short (%d bytes, need >=32)", len(c.JWTSecret))
	}

	ttl, err := time.ParseDuration(envOr("ZL_JWT_TTL", "168h")) // 7 days
	if err != nil {
		return nil, fmt.Errorf("config: ZL_JWT_TTL invalid: %w", err)
	}
	c.JWTTTL = ttl

	// TLS cert and key must be supplied together. Catch the "set one,
	// forgot the other" misconfiguration at startup rather than on the
	// first request.
	if (c.TLSCertPath == "") != (c.TLSKeyPath == "") {
		return nil, errors.New(
			"config: ZL_TLS_CERT_PATH and ZL_TLS_KEY_PATH must both be set or both empty")
	}

	return c, nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envBool(k string, def bool) bool {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}
