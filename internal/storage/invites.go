// Package storage — invites repo.
//
// Batch 3a additions:
//   - MintWithOptions: takes expires_in and note (replaces / supplements Mint).
//   - Extend: push an invite's expires_at forward.
//   - Delete: remove an invite and (optionally) cascade to the user registered
//     with it. cascade is opt-in because the DB-level cascade would be too
//     aggressive for normal "revoke unused code" cleanups.

package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"errors"
	"strings"
	"time"
)

// Invite is the row shape for the invites table.
//
// B4.7 supplement / B4: CreatedBy and UsedBy are both nullable since
// migration 0006 changed both FK references to ON DELETE SET NULL.
// A NULL CreatedBy means the creator has been deleted from the system;
// a NULL UsedBy means the consumer was deleted but the invite was
// previously consumed (UsedAt is the authoritative consumed-marker).
type Invite struct {
	Code      string
	CreatedBy *int64
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedBy    *int64
	UsedAt    *time.Time
	Note      string
}

// IsConsumed reports whether the invite has been redeemed. After
// migration 0006 (FK SET NULL), UsedBy can be nulled when the
// consuming user is deleted post-consume; UsedAt remains as the
// authoritative consumed-marker timestamp.
func (i *Invite) IsConsumed() bool { return i.UsedAt != nil }

// IsExpired reports whether the invite is past its expiry timestamp.
func (i *Invite) IsExpired() bool { return time.Now().After(i.ExpiresAt) }

// InviteRepo holds CRUD on the invites table.
type InviteRepo struct{ db *sql.DB }

func newInviteRepo(db *sql.DB) *InviteRepo { return &InviteRepo{db: db} }

// Get fetches an invite by code.
func (r *InviteRepo) Get(ctx context.Context, code string) (*Invite, error) {
	row := r.db.QueryRowContext(ctx, selectInviteSQL, code)
	return scanInvite(row)
}

// List returns all invites in creation order (newest last; handlers sort for UI).
func (r *InviteRepo) List(ctx context.Context) ([]*Invite, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT code, created_by, created_at, expires_at, used_by, used_at, COALESCE(note,'')
		   FROM invites ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Invite
	for rows.Next() {
		inv, err := scanInvite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, inv)
	}
	return out, rows.Err()
}

// MintOptions configures a batch mint operation.
type MintOptions struct {
	// Count is the number of codes to generate (1..50).
	Count int
	// ExpiresIn is the TTL. If zero, defaults to 7 days (matches original Phase 1).
	ExpiresIn time.Duration
	// Note is a per-batch annotation. Optional.
	Note string
	// CreatedBy is the admin's user id. Required.
	CreatedBy int64
}

// MintWithOptions generates Count invite codes in one transaction. Codes are
// 8 ASCII chars, base32 no-padding, formatted as XXXX-XXXX for readability.
func (r *InviteRepo) MintWithOptions(ctx context.Context, opts MintOptions) ([]*Invite, error) {
	if opts.Count < 1 {
		return nil, errors.New("count must be >=1")
	}
	if opts.Count > 50 {
		return nil, errors.New("count must be <=50")
	}
	if opts.CreatedBy <= 0 {
		return nil, errors.New("createdBy required")
	}
	if opts.ExpiresIn <= 0 {
		opts.ExpiresIn = 7 * 24 * time.Hour
	}
	expiresAt := time.Now().Add(opts.ExpiresIn).UTC()

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	var out []*Invite
	for i := 0; i < opts.Count; i++ {
		code, err := generateInviteCode()
		if err != nil {
			return nil, err
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO invites (code, created_by, expires_at, note)
			VALUES (?, ?, ?, ?)
		`, code, opts.CreatedBy, expiresAt, opts.Note)
		if err != nil {
			if isUniqueErr(err) {
				// Rare: collision in 40-bit space. Retry by decrementing i.
				i--
				continue
			}
			return nil, err
		}
		createdByCopy := opts.CreatedBy
		out = append(out, &Invite{
			Code:      code,
			CreatedBy: &createdByCopy,
			CreatedAt: time.Now().UTC(),
			ExpiresAt: expiresAt,
			Note:      opts.Note,
		})
	}
	return out, tx.Commit()
}

// Consume marks an invite as used by userID. Returns ErrInviteUnusable if the
// invite is missing, already used, or expired.
func (r *InviteRepo) Consume(ctx context.Context, code string, userID int64) error {
	now := time.Now().UTC()
	res, err := r.db.ExecContext(ctx, `
		UPDATE invites
		   SET used_by = ?, used_at = ?
		 WHERE code = ?
		   AND used_at IS NULL
		   AND expires_at > ?
	`, userID, now, code, now)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrInviteUnusable
	}
	return nil
}

// Extend pushes an invite's expires_at forward by the given duration.
// Returns ErrInviteUnusable if the invite is already used.
func (r *InviteRepo) Extend(ctx context.Context, code string, by time.Duration) error {
	if by <= 0 {
		return errors.New("extension must be positive")
	}
	// Fetch first so we can compute based on the later of (now, existing exp).
	inv, err := r.Get(ctx, code)
	if err != nil {
		return err
	}
	if inv.IsConsumed() {
		return ErrInviteUnusable
	}
	base := inv.ExpiresAt
	if time.Now().After(base) {
		base = time.Now()
	}
	newExp := base.Add(by).UTC()
	_, err = r.db.ExecContext(ctx,
		`UPDATE invites SET expires_at = ? WHERE code = ?`, newExp, code)
	return err
}

// Delete removes an invite. If cascade=true AND the invite has been used,
// the associated user is also deleted (and by FK cascade, everything they
// own — subscriptions, revoked_tokens, etc).
//
// Returns ErrNotFound if the code doesn't exist. Returns the deleted user id
// (if any) so the caller can revoke tokens / audit log it.
func (r *InviteRepo) Delete(ctx context.Context, code string, cascade bool) (deletedUserID *int64, err error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	var usedBy sql.NullInt64
	if err := tx.QueryRowContext(ctx,
		`SELECT used_by FROM invites WHERE code = ?`, code).Scan(&usedBy); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	if cascade && usedBy.Valid {
		if _, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, usedBy.Int64); err != nil {
			return nil, err
		}
		uid := usedBy.Int64
		deletedUserID = &uid
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM invites WHERE code = ?`, code); err != nil {
		return nil, err
	}
	return deletedUserID, tx.Commit()
}

// ----- SQL & scanning ---------------------------------------------------------

const selectInviteSQL = `
	SELECT code, created_by, created_at, expires_at, used_by, used_at, COALESCE(note,'')
	  FROM invites
	 WHERE code = ?
`

func scanInvite(s scanner) (*Invite, error) {
	var inv Invite
	var createdBy sql.NullInt64
	var usedBy sql.NullInt64
	var usedAt sql.NullTime
	err := s.Scan(&inv.Code, &createdBy, &inv.CreatedAt, &inv.ExpiresAt,
		&usedBy, &usedAt, &inv.Note)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if createdBy.Valid {
		c := createdBy.Int64
		inv.CreatedBy = &c
	}
	if usedBy.Valid {
		u := usedBy.Int64
		inv.UsedBy = &u
	}
	if usedAt.Valid {
		t := usedAt.Time
		inv.UsedAt = &t
	}
	return &inv, nil
}

// generateInviteCode returns an 8-char code formatted as XXXX-XXXX, using the
// base32 alphabet minus ambiguous characters (I/L/O/0 collapsed).
func generateInviteCode() (string, error) {
	// 5 random bytes -> 8 base32 chars.
	var raw [5]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	s := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw[:])
	// Replace ambiguous chars with clearer ones.
	s = strings.NewReplacer("0", "Z", "1", "Y", "O", "X", "I", "W", "L", "V").
		Replace(s)
	return s[:4] + "-" + s[4:8], nil
}

// ErrInviteUnusable indicates the invite is missing, already consumed, or expired.
var ErrInviteUnusable = errors.New("invite is not usable")
