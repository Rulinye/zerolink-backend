// Package storage — subscriptions repo.
//
// Batch 3a changes:
//   - Create now uses RETURNING to populate created_at properly (F12 fix).
//     Phase 1 INSERT ... returned a Subscription with zero CreatedAt because
//     DEFAULT CURRENT_TIMESTAMP fires server-side and the Go struct was built
//     from inputs alone. Switched to INSERT ... RETURNING (SQLite 3.35+) so
//     the row returned has the DB-assigned timestamp.

package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"
)

// Subscription is one Clash subscription URL owned by a user.
type Subscription struct {
	Token         string
	UserID        int64
	Name          string
	CreatedAt     time.Time
	LastFetchedAt *time.Time
	FetchCount    int64
	Revoked       bool
}

// SubscriptionRepo holds CRUD on subscriptions.
type SubscriptionRepo struct{ db *sql.DB }

func newSubscriptionRepo(db *sql.DB) *SubscriptionRepo { return &SubscriptionRepo{db: db} }

// Create inserts a new subscription row with a freshly generated token.
// Uses INSERT ... RETURNING so created_at is populated from the DB default
// rather than left as Go's zero Time (F12 fix).
func (r *SubscriptionRepo) Create(ctx context.Context, userID int64, name string) (*Subscription, error) {
	token, err := generateSubToken()
	if err != nil {
		return nil, err
	}
	var sub Subscription
	var revoked int
	err = r.db.QueryRowContext(ctx, `
		INSERT INTO subscriptions (token, user_id, name) VALUES (?, ?, ?)
		RETURNING token, user_id, name, created_at, last_fetched_at, fetch_count, revoked
	`, token, userID, name).Scan(
		&sub.Token, &sub.UserID, &sub.Name, &sub.CreatedAt,
		&nullTimePtr{&sub.LastFetchedAt}, &sub.FetchCount, &revoked,
	)
	if err != nil {
		return nil, err
	}
	sub.Revoked = revoked != 0
	return &sub, nil
}

// ListByUser returns all subscriptions owned by user, newest first.
func (r *SubscriptionRepo) ListByUser(ctx context.Context, userID int64) ([]*Subscription, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT token, user_id, name, created_at, last_fetched_at, fetch_count, revoked
		  FROM subscriptions
		 WHERE user_id = ?
		 ORDER BY created_at DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Subscription
	for rows.Next() {
		s, err := scanSub(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// GetByToken fetches by token (used by /sub/{token} handler; not auth-gated).
func (r *SubscriptionRepo) GetByToken(ctx context.Context, token string) (*Subscription, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT token, user_id, name, created_at, last_fetched_at, fetch_count, revoked
		  FROM subscriptions WHERE token = ?
	`, token)
	return scanSub(row)
}

// TouchFetch increments fetch_count and updates last_fetched_at.
func (r *SubscriptionRepo) TouchFetch(ctx context.Context, token string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE subscriptions
		   SET fetch_count = fetch_count + 1,
		       last_fetched_at = CURRENT_TIMESTAMP
		 WHERE token = ?
	`, token)
	return err
}

// Revoke flags a subscription as revoked. Future fetches will return 410 Gone.
func (r *SubscriptionRepo) Revoke(ctx context.Context, token string, userID int64) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE subscriptions SET revoked = 1
		WHERE token = ? AND user_id = ?
	`, token, userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ----- scanning ---------------------------------------------------------------

func scanSub(s scanner) (*Subscription, error) {
	var sub Subscription
	var lastFetched sql.NullTime
	var revoked int
	err := s.Scan(&sub.Token, &sub.UserID, &sub.Name, &sub.CreatedAt,
		&lastFetched, &sub.FetchCount, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if lastFetched.Valid {
		t := lastFetched.Time
		sub.LastFetchedAt = &t
	}
	sub.Revoked = revoked != 0
	return &sub, nil
}

// nullTimePtr is a tiny shim that satisfies sql.Scanner and stores the result
// into a **time.Time pointer, so callers can feed it to Scan in one line.
type nullTimePtr struct{ dst **time.Time }

func (n *nullTimePtr) Scan(src any) error {
	if src == nil {
		*n.dst = nil
		return nil
	}
	var nt sql.NullTime
	if err := nt.Scan(src); err != nil {
		return err
	}
	if !nt.Valid {
		*n.dst = nil
		return nil
	}
	t := nt.Time
	*n.dst = &t
	return nil
}

// generateSubToken returns a 32-char hex token (128 bits of entropy).
func generateSubToken() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}
