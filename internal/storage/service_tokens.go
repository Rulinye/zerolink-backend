// Package storage — service_tokens repo (Batch 3.3 Group 1a).
//
// service_tokens are Bearer credentials issued to internal services
// (currently: broker daemons) so they can authenticate to backend's
// /api/v1/auth/verify endpoint when reverse-validating a client JWT.
//
// One token per broker, provisioned via Ansible vault at deploy time.
// Stored hashed (sha256, lowercase hex). The plaintext is shown once
// at gen time by `cmd/gen-service-token` and then forgotten by the
// backend.
//
// Lifecycle:
//   1. Operator runs `gen-service-token --label broker-gz` on the
//      backend host -> stdout prints the plaintext.
//   2. Operator pastes the plaintext into the Ansible vault under
//      service_tokens.broker_gz.
//   3. roles/broker/ deploys the broker with the token in env.
//   4. Broker calls /auth/verify with `Authorization: Bearer <token>`.
//   5. Rotation: provision new token, deploy, verify, then Disable old.

package storage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"
)

// ServiceToken is the metadata view of a service token. The plaintext is
// never stored after creation; only its sha256 hash lives in the DB.
type ServiceToken struct {
	ID         int64
	Label      string // 'broker-gz', 'broker-kr', etc.
	CreatedAt  time.Time
	LastUsedAt *time.Time
	Disabled   bool
}

// ServiceTokenRepo holds CRUD on the service_tokens table.
type ServiceTokenRepo struct{ db *sql.DB }

func newServiceTokenRepo(db *sql.DB) *ServiceTokenRepo { return &ServiceTokenRepo{db: db} }

// ErrServiceTokenInvalid is returned by Verify when the plaintext doesn't
// match any active token (no row, hash mismatch, or disabled=1). Callers
// should treat this as 401 unauthorized — do not differentiate between
// "no such token" and "disabled" in the response, to avoid leaking
// label existence to attackers.
var ErrServiceTokenInvalid = errors.New("storage: service token invalid")

// Create generates a new random Bearer token, stores its sha256 hash,
// and returns the plaintext. The caller is responsible for delivering
// the plaintext to the operator (the gen-service-token CLI prints it
// to stdout).
//
// Token format: 32 random bytes -> base64url-no-padding (43 chars).
// 256 bits of entropy is overkill for a server-to-server credential
// but cheap and obvious.
func (r *ServiceTokenRepo) Create(ctx context.Context, label string) (plaintext string, err error) {
	if label == "" {
		return "", errors.New("storage: service token label required")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	plaintext = base64.RawURLEncoding.EncodeToString(raw)
	tokenHash := hashServiceToken(plaintext)

	_, err = r.db.ExecContext(ctx, `
		INSERT INTO service_tokens (label, token_hash, created_at, disabled)
		VALUES (?, ?, CURRENT_TIMESTAMP, 0)
	`, label, tokenHash)
	if err != nil {
		if isUniqueErr(err) {
			return "", errors.New("storage: service token label already exists")
		}
		return "", err
	}
	return plaintext, nil
}

// Verify hashes the plaintext and looks up an active (non-disabled) token.
// Returns ErrServiceTokenInvalid for any failure mode (missing row, hash
// mismatch, disabled). Callers should NOT distinguish between these in
// the HTTP response.
//
// Note: there is no constant-time comparison in the application layer
// because the lookup happens by sha256 hash equality on a TEXT column,
// which is bounded by the index B-tree comparison and not by token
// content. Timing differences are dominated by query overhead and are
// not exploitable.
func (r *ServiceTokenRepo) Verify(ctx context.Context, plaintext string) (*ServiceToken, error) {
	if plaintext == "" {
		return nil, ErrServiceTokenInvalid
	}
	tokenHash := hashServiceToken(plaintext)
	row := r.db.QueryRowContext(ctx, `
		SELECT id, label, created_at, last_used_at, disabled
		  FROM service_tokens
		 WHERE token_hash = ?
	`, tokenHash)
	var t ServiceToken
	var lastUsed sql.NullTime
	var disabled int
	if err := row.Scan(&t.ID, &t.Label, &t.CreatedAt, &lastUsed, &disabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrServiceTokenInvalid
		}
		return nil, err
	}
	if disabled != 0 {
		return nil, ErrServiceTokenInvalid
	}
	t.Disabled = false
	if lastUsed.Valid {
		t.LastUsedAt = &lastUsed.Time
	}
	return &t, nil
}

// TouchLastUsed updates last_used_at to now. Best-effort — callers
// should ignore errors and not block the request path on this. Used
// by the /auth/verify handler to surface "is broker-kr alive?" in
// admin UI.
func (r *ServiceTokenRepo) TouchLastUsed(ctx context.Context, id int64) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE service_tokens SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?`, id)
	return err
}

// List returns all service tokens (without hashes — those are write-only
// from the application's perspective). Used by admin UI / CLI.
func (r *ServiceTokenRepo) List(ctx context.Context) ([]*ServiceToken, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, label, created_at, last_used_at, disabled
		  FROM service_tokens
		 ORDER BY id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ServiceToken
	for rows.Next() {
		var t ServiceToken
		var lastUsed sql.NullTime
		var disabled int
		if err := rows.Scan(&t.ID, &t.Label, &t.CreatedAt, &lastUsed, &disabled); err != nil {
			return nil, err
		}
		t.Disabled = disabled != 0
		if lastUsed.Valid {
			t.LastUsedAt = &lastUsed.Time
		}
		out = append(out, &t)
	}
	return out, rows.Err()
}

// Disable marks a token as disabled. Used during broker rotation:
// provision new token, deploy, verify it works, then Disable old.
// Returns ErrNotFound if no row matches the label.
func (r *ServiceTokenRepo) Disable(ctx context.Context, label string) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE service_tokens SET disabled = 1 WHERE label = ?`, label)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// hashServiceToken returns the lowercase-hex sha256 of the plaintext
// token, matching what we store in service_tokens.token_hash. Kept as
// a separate function so the gen CLI and Verify path use identical
// derivation.
func hashServiceToken(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}
