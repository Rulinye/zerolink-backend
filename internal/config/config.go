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
	// Listen is the HTTP listen address, e.g. "127.0.0.1:8080".
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
