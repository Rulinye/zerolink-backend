package storage

import (
	"context"
	"database/sql"
	"time"
)

// TrafficRepo holds CRUD on the traffic table. Phase 1 only inserts; Phase 4
// will add aggregation queries.
type TrafficRepo struct{ db *sql.DB }

// Record appends a single traffic data point. Phase 1 backend doesn't actually
// produce these rows yet; the table exists so the schema is stable when Phase 3
// vswitch starts reporting.
func (r *TrafficRepo) Record(ctx context.Context, userID int64, nodeID *int64, up, down int64) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO traffic (user_id, node_id, bytes_up, bytes_down)
		VALUES (?, ?, ?, ?)
	`, userID, nodeID, up, down)
	return err
}

// RevokedTokenRepo persists JWT jti values that should be rejected by the
// auth middleware regardless of their exp.
type RevokedTokenRepo struct{ db *sql.DB }

// Add inserts a revoked-token entry. expiresAt should be the original token's
// exp claim so we can GC the row after that point.
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
		`SELECT 1 FROM revoked_tokens WHERE jti = ? LIMIT 1`, jti).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// GC deletes revoked-token rows whose expires_at is in the past. Should be
// called periodically (e.g. once per day) by a background goroutine.
func (r *RevokedTokenRepo) GC(ctx context.Context) (int64, error) {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM revoked_tokens WHERE expires_at < CURRENT_TIMESTAMP`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
