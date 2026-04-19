// Package storage — revoked JWT tracking.
//
// The revoked_tokens table was created in Phase 1. Batch 3a adds:
//   - RevokeAllForUser: mass-revoke (used by admin disable, change password, new login)
//   - IsRevokedByJTI stays as-is (signature unchanged)
//   - GCExpired cleans up rows whose expires_at is in the past, called periodically

package storage

import (
	"context"
	"database/sql"
	"time"
)

// RevokedTokenRepo persists JWT jti values that should be rejected by the
// auth middleware regardless of their exp.
type RevokedTokenRepo struct{ db *sql.DB }

func newRevokedTokenRepo(db *sql.DB) *RevokedTokenRepo { return &RevokedTokenRepo{db: db} }

// Add inserts a revoked-token entry. expiresAt should be the original token's
// exp claim so the GC job can drop rows after that point.
func (r *RevokedTokenRepo) Add(ctx context.Context, jti string, userID int64, expiresAt time.Time) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO revoked_tokens (jti, user_id, expires_at) VALUES (?, ?, ?)
		ON CONFLICT(jti) DO NOTHING
	`, jti, userID, expiresAt)
	return err
}

// IsRevoked reports whether a jti is on the revocation list.
func (r *RevokedTokenRepo) IsRevoked(ctx context.Context, jti string) (bool, error) {
	var one int
	err := r.db.QueryRowContext(ctx,
		`SELECT 1 FROM revoked_tokens WHERE jti = ?`, jti).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// RevokeAllForUser inserts a placeholder record that makes the middleware
// treat ALL tokens issued to userID (whose iat is before now) as revoked.
//
// Implementation note: instead of enumerating all outstanding jti (we don't
// track them on issue), we rely on the middleware checking `iat < users.password_changed_at`
// for the user-id-wide case. However for "admin disable" we DO want an
// immediate kill without bumping password_changed_at — so this method also
// updates a separate bookkeeping field.
//
// For simplicity in this phase, we piggyback on password_changed_at: any
// user-wide revocation bumps it. When Phase 3+ needs finer-grained revocation
// (e.g. only revoke sessions older than 1 hour), we'll add a separate
// `tokens_invalid_before` column.
func (r *RevokedTokenRepo) RevokeAllForUser(ctx context.Context, userID int64) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE users SET password_changed_at = CURRENT_TIMESTAMP WHERE id = ?
	`, userID)
	return err
}

// GCExpired removes revoked_tokens whose expires_at has passed. Returns the
// number of rows deleted. Safe to call periodically from a background job.
func (r *RevokedTokenRepo) GCExpired(ctx context.Context) (int64, error) {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM revoked_tokens WHERE expires_at < CURRENT_TIMESTAMP`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}
