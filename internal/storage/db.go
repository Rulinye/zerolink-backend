// Package storage owns the SQLite connection and all repository types.
//
// Design notes:
//   - The DB is opened with a single writer connection and an unlimited reader pool.
//     SQLite serializes writes regardless; using one writer connection avoids
//     "database is locked" surprises under concurrent writes.
//   - WAL mode is enabled by the init migration. busy_timeout is set on each
//     connection by the connector below.
//   - Migrations are embedded via go:embed and applied in lexical order on Open().
//     Phase 1 deliberately avoids the golang-migrate library; with a single
//     migration file the handwritten runner is ~30 lines and zero deps.
//     When Phase 4 introduces schema diffs, swap to golang-migrate.
package storage

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// DB wraps a *sql.DB and the repository types built on top.
type DB struct {
	conn *sql.DB

	Users         *UserRepo
	Invites       *InviteRepo
	Nodes         *NodeRepo
	Subscriptions *SubscriptionRepo
	Traffic       *TrafficRepo
	Tokens        *RevokedTokenRepo
}

// Open opens (or creates) the SQLite database at path, applies any pending
// "up" migrations, and returns a ready-to-use DB.
//
// The connection string sets busy_timeout so concurrent writers wait instead
// of failing with SQLITE_BUSY, and forces foreign keys ON.
func Open(path string) (*DB, error) {
	dsn := fmt.Sprintf(
		"file:%s?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)",
		path,
	)
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// SQLite is single-writer; cap to a small pool so we don't waste FDs.
	conn.SetMaxOpenConns(8)
	conn.SetMaxIdleConns(2)
	conn.SetConnMaxLifetime(time.Hour)

	if err := conn.Ping(); err != nil {
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}

	if err := applyMigrations(conn); err != nil {
		return nil, fmt.Errorf("apply migrations: %w", err)
	}

	db := &DB{conn: conn}
	db.Users = &UserRepo{db: conn}
	db.Invites = &InviteRepo{db: conn}
	db.Nodes = &NodeRepo{db: conn}
	db.Subscriptions = &SubscriptionRepo{db: conn}
	db.Traffic = &TrafficRepo{db: conn}
	db.Tokens = &RevokedTokenRepo{db: conn}
	return db, nil
}

// Conn exposes the underlying *sql.DB for tests and advanced callers.
func (d *DB) Conn() *sql.DB { return d.conn }

// Close releases the underlying connection pool.
func (d *DB) Close() error { return d.conn.Close() }

// applyMigrations runs every *.up.sql in migrations/ exactly once. It uses a
// schema_migrations table compatible with golang-migrate's layout, so a future
// switch is trivial.
func applyMigrations(db *sql.DB) error {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version BIGINT PRIMARY KEY,
			dirty   BOOLEAN NOT NULL DEFAULT 0
		)
	`); err != nil {
		return err
	}

	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return err
	}
	type mig struct {
		version int64
		name    string
	}
	var ups []mig
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".up.sql") {
			continue
		}
		// Filename format: NNNN_label.up.sql
		var v int64
		if _, err := fmt.Sscanf(name, "%d_", &v); err != nil {
			return fmt.Errorf("migration %q: cannot parse version: %w", name, err)
		}
		ups = append(ups, mig{version: v, name: name})
	}
	sort.Slice(ups, func(i, j int) bool { return ups[i].version < ups[j].version })

	for _, m := range ups {
		var applied bool
		err := db.QueryRow(
			`SELECT 1 FROM schema_migrations WHERE version = ?`, m.version,
		).Scan(new(int))
		switch {
		case errors.Is(err, sql.ErrNoRows):
			applied = false
		case err != nil:
			return err
		default:
			applied = true
		}
		if applied {
			continue
		}

		raw, err := migrationFS.ReadFile("migrations/" + m.name)
		if err != nil {
			return err
		}

		// SQLite's database/sql driver can execute multi-statement scripts
		// when fed as one string. We do not wrap in a transaction because
		// some statements (PRAGMA journal_mode) cannot run inside one.
		if _, err := db.Exec(string(raw)); err != nil {
			return fmt.Errorf("migration %s: %w", m.name, err)
		}
		if _, err := db.Exec(
			`INSERT INTO schema_migrations (version, dirty) VALUES (?, 0)`, m.version,
		); err != nil {
			return err
		}
	}
	return nil
}
