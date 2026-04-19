// Package cron — light background workers.
//
// Batch 3a ships the monthly quota-reset worker + revoked_tokens GC. Both
// are simple "wake up every minute, do due work, sleep" loops. They run in
// the same process as the HTTP server; no external scheduler needed.

package cron

import (
	"context"
	"log/slog"
	"time"

	"github.com/rulinye/zerolink-backend/internal/storage"
)

// Run launches the cron workers. Returns immediately; the workers stop when
// the passed context is cancelled.
//
// Both workers are idempotent — safe to run multiple instances of the
// backend process simultaneously (not that Phase 1 deploys multi-instance,
// but this keeps it future-proof).
func Run(ctx context.Context, db *storage.DB, log *slog.Logger) {
	go quotaResetLoop(ctx, db, log)
	go revokedGCLoop(ctx, db, log)
}

// quotaResetLoop wakes every minute. For any users whose quota_reset_at has
// passed, zeros used_bytes and advances quota_reset_at to the 1st of the
// following month.
//
// Batch size cap = 500 per tick so a massive backlog after downtime doesn't
// hammer the DB. If there are more than 500 due, they'll drain over
// subsequent ticks.
func quotaResetLoop(ctx context.Context, db *storage.DB, log *slog.Logger) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	tick := func() {
		ids, err := db.Users.PickDueForQuotaReset(ctx, 500)
		if err != nil {
			log.Error("cron.quota_reset: pick failed", "err", err)
			return
		}
		for _, id := range ids {
			if err := db.Users.ResetUsedBytes(ctx, id); err != nil {
				log.Error("cron.quota_reset: reset failed", "user_id", id, "err", err)
			}
		}
		if len(ids) > 0 {
			log.Info("cron.quota_reset: reset users", "count", len(ids))
		}
	}

	// Prime run at startup so a server that was down during 1st-of-month
	// catches up immediately rather than waiting 60s.
	tick()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tick()
		}
	}
}

// revokedGCLoop cleans up revoked_tokens rows whose expires_at has passed.
// Runs once an hour; the table is small enough that this is basically free.
func revokedGCLoop(ctx context.Context, db *storage.DB, log *slog.Logger) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, err := db.Tokens.GCExpired(ctx)
			if err != nil {
				log.Error("cron.revoked_gc: failed", "err", err)
				continue
			}
			if n > 0 {
				log.Info("cron.revoked_gc: cleaned", "count", n)
			}
		}
	}
}
