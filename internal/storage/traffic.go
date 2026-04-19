package storage

import (
	"context"
	"database/sql"
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
