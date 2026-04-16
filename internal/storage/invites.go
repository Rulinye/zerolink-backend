package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Invite represents a one-shot invitation code created by an admin.
type Invite struct {
	Code      string
	CreatedBy int64
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedBy    *int64
	UsedAt    *time.Time
	Note      string
}

// IsConsumed reports whether the invite has been redeemed.
func (i *Invite) IsConsumed() bool { return i.UsedBy != nil }

// IsExpired reports whether the invite is past its expiry timestamp.
func (i *Invite) IsExpired() bool { return time.Now().After(i.ExpiresAt) }

// InviteRepo holds CRUD on the invites table.
type InviteRepo struct{ db *sql.DB }

// ErrInviteUsed signals an attempt to redeem an already-consumed code.
var ErrInviteUsed = errors.New("storage: invite already used")

// ErrInviteExpired signals an attempt to redeem an expired code.
var ErrInviteExpired = errors.New("storage: invite expired")

// Insert creates a new invite. The code is provided by the caller (we do not
// generate it here so the handler can show the human-readable code immediately).
func (r *InviteRepo) Insert(ctx context.Context, in *Invite) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO invites (code, created_by, expires_at, note)
		VALUES (?, ?, ?, ?)
	`, in.Code, in.CreatedBy, in.ExpiresAt, in.Note)
	if isUniqueErr(err) {
		// Caller should retry with a new code.
		return errors.New("storage: invite code collision")
	}
	return err
}

// Get loads an invite by its code. Returns ErrNotFound if missing.
func (r *InviteRepo) Get(ctx context.Context, code string) (*Invite, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT code, created_by, created_at, expires_at, used_by, used_at, note
		FROM invites WHERE code = ?
	`, code)
	return scanInvite(row)
}

// Consume marks the invite as redeemed by userID. It is atomic: if the row is
// already consumed (or doesn't exist), returns ErrInviteUsed/ErrNotFound.
// It also enforces the expiry check.
func (r *InviteRepo) Consume(ctx context.Context, code string, userID int64) error {
	// We use an UPDATE ... WHERE used_by IS NULL to make this race-free.
	res, err := r.db.ExecContext(ctx, `
		UPDATE invites
		   SET used_by = ?, used_at = CURRENT_TIMESTAMP
		 WHERE code = ?
		   AND used_by IS NULL
		   AND expires_at > CURRENT_TIMESTAMP
	`, userID, code)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 1 {
		return nil
	}
	// Disambiguate the failure mode for a useful error message.
	in, err := r.Get(ctx, code)
	if err != nil {
		return err // ErrNotFound surfaces here
	}
	if in.IsConsumed() {
		return ErrInviteUsed
	}
	if in.IsExpired() {
		return ErrInviteExpired
	}
	// Unreachable under correct schema.
	return errors.New("storage: invite consume failed for unknown reason")
}

// List returns invites in reverse-chronological order. If onlyUnused is true,
// already-consumed codes are filtered out.
func (r *InviteRepo) List(ctx context.Context, onlyUnused bool) ([]*Invite, error) {
	q := `SELECT code, created_by, created_at, expires_at, used_by, used_at, note
	      FROM invites`
	if onlyUnused {
		q += ` WHERE used_by IS NULL`
	}
	q += ` ORDER BY created_at DESC`
	rows, err := r.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Invite
	for rows.Next() {
		in, err := scanInvite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

func scanInvite(s scanner) (*Invite, error) {
	var in Invite
	var usedBy sql.NullInt64
	var usedAt sql.NullTime
	var note sql.NullString
	err := s.Scan(&in.Code, &in.CreatedBy, &in.CreatedAt, &in.ExpiresAt, &usedBy, &usedAt, &note)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if usedBy.Valid {
		v := usedBy.Int64
		in.UsedBy = &v
	}
	if usedAt.Valid {
		t := usedAt.Time
		in.UsedAt = &t
	}
	if note.Valid {
		in.Note = note.String
	}
	return &in, nil
}
