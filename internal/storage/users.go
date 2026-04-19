// Package storage — users repo.
//
// Batch 3a (Phase 2 followup) changes:
//   - User struct gains DisabledUntil / QuotaBytes / UsedBytes / QuotaResetAt
//     / PasswordChangedAt fields.
//   - New methods: SetPassword, SetDisabled, SetQuota, AddUsedBytes,
//     PickDueForQuotaReset, ResetUsedBytes.
//   - IsEffectivelyDisabled helper centralizes the "is this user currently
//     banned" logic so middleware and handlers stay consistent.

package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// User is the row-level representation of an account.
type User struct {
	ID           int64
	Username     string
	PasswordHash string
	IsAdmin      bool
	IsDisabled   bool // legacy — true = permanent ban when DisabledUntil is NULL
	CreatedAt    time.Time
	LastLoginAt  *time.Time

	// Batch 3a additions.

	// DisabledUntil, when non-nil and in the future, means the user is
	// currently banned. nil + IsDisabled=true means "permanent". nil +
	// IsDisabled=false means "not disabled".
	DisabledUntil *time.Time

	// QuotaBytes is the monthly cap. nil means unlimited.
	QuotaBytes *int64

	// UsedBytes is the running counter for the current billing period.
	UsedBytes int64

	// QuotaResetAt is when UsedBytes will next be zeroed.
	QuotaResetAt *time.Time

	// PasswordChangedAt, when non-nil, invalidates any JWT whose iat is
	// before this timestamp. Enables "change password -> log out everywhere".
	PasswordChangedAt *time.Time
}

// IsEffectivelyDisabled reports whether this user should be treated as banned
// right now. Called by the JWT middleware (F15) and admin handlers.
//
// Semantics:
//   - DisabledUntil > now()  -> banned (timed)
//   - DisabledUntil <= now() -> NOT banned (auto-expired; treat as clear)
//   - DisabledUntil nil + IsDisabled=true  -> banned (permanent)
//   - DisabledUntil nil + IsDisabled=false -> not banned
func (u *User) IsEffectivelyDisabled(now time.Time) bool {
	if u.DisabledUntil != nil {
		return u.DisabledUntil.After(now)
	}
	return u.IsDisabled
}

// UserRepo is the repository for the users table.
type UserRepo struct{ db *sql.DB }

func newUserRepo(db *sql.DB) *UserRepo { return &UserRepo{db: db} }

// GetByID fetches a user by primary key.
func (r *UserRepo) GetByID(ctx context.Context, id int64) (*User, error) {
	row := r.db.QueryRowContext(ctx, selectUserByIDSQL, id)
	return scanUser(row)
}

// GetByUsername fetches a user by (unique) username.
func (r *UserRepo) GetByUsername(ctx context.Context, username string) (*User, error) {
	row := r.db.QueryRowContext(ctx, selectUserByUsernameSQL, username)
	return scanUser(row)
}

// Create inserts a new user. Returns the full row (with auto-assigned id +
// server-generated timestamps).
func (r *UserRepo) Create(ctx context.Context, username, passwordHash string, isAdmin bool) (*User, error) {
	// Default quota = 100 GB; reset = 1st of next month, server local TZ.
	defaultQuota := int64(100) * 1024 * 1024 * 1024
	nextReset := firstOfNextMonthLocal(time.Now())

	res, err := r.db.ExecContext(ctx, `
		INSERT INTO users (username, password_hash, is_admin, is_disabled,
		                   quota_bytes, used_bytes, quota_reset_at)
		VALUES (?, ?, ?, 0, ?, 0, ?)
	`, username, passwordHash, boolToInt(isAdmin), defaultQuota, nextReset)
	if err != nil {
		if isUniqueErr(err) {
			return nil, ErrUsernameTaken
		}
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	return r.GetByID(ctx, id)
}

// UpdateLastLogin sets last_login_at=now() for the user.
func (r *UserRepo) UpdateLastLogin(ctx context.Context, id int64) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?`, id)
	return err
}

// List returns all users ordered by id.
func (r *UserRepo) List(ctx context.Context) ([]*User, error) {
	rows, err := r.db.QueryContext(ctx, selectAllUsersSQL)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// Count returns the total user count.
func (r *UserRepo) Count(ctx context.Context) (int64, error) {
	var n int64
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// ----- Batch 3a additions -----------------------------------------------------

// SetPassword updates the user's bcrypt hash and bumps password_changed_at.
// Callers should follow this with TokenRevoker.RevokeAllForUser to log the
// user out everywhere (F17 requirement).
func (r *UserRepo) SetPassword(ctx context.Context, id int64, newHash string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE users
		   SET password_hash = ?,
		       password_changed_at = CURRENT_TIMESTAMP
		 WHERE id = ?
	`, newHash, id)
	return err
}

// SetDisabled updates the ban state of a user.
//
//   - disable=false -> clears both is_disabled and disabled_until.
//   - disable=true  + until=nil -> permanent ban (is_disabled=1, disabled_until=NULL).
//   - disable=true  + until=non-nil -> timed ban.
func (r *UserRepo) SetDisabled(ctx context.Context, id int64, disable bool, until *time.Time) error {
	if !disable {
		_, err := r.db.ExecContext(ctx, `
			UPDATE users SET is_disabled = 0, disabled_until = NULL
			 WHERE id = ?
		`, id)
		return err
	}
	// Timed ban: keep is_disabled=1 during the window for legacy checks; clear after.
	var untilVal any
	if until != nil {
		untilVal = until.UTC()
	}
	_, err := r.db.ExecContext(ctx, `
		UPDATE users SET is_disabled = 1, disabled_until = ?
		 WHERE id = ?
	`, untilVal, id)
	return err
}

// SetQuota updates the monthly cap. pass nil for unlimited.
//
// Validation: caller MUST ensure newQuota >= current used_bytes when non-nil;
// this method does not enforce it (handler does the check with a clearer
// error message to the user).
func (r *UserRepo) SetQuota(ctx context.Context, id int64, newQuota *int64) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE users SET quota_bytes = ? WHERE id = ?`, newQuota, id)
	return err
}

// AddUsedBytes atomically increments used_bytes. Called by Phase 3 vswitch
// via an internal API (not in Batch 3a), exposed here so handler logic has
// a place to hang off of.
func (r *UserRepo) AddUsedBytes(ctx context.Context, id int64, delta int64) error {
	if delta == 0 {
		return nil
	}
	_, err := r.db.ExecContext(ctx,
		`UPDATE users SET used_bytes = used_bytes + ? WHERE id = ?`, delta, id)
	return err
}

// PickDueForQuotaReset returns up to max user ids whose quota_reset_at is
// in the past. Used by the monthly reset worker.
func (r *UserRepo) PickDueForQuotaReset(ctx context.Context, max int) ([]int64, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id FROM users
		 WHERE quota_reset_at IS NOT NULL
		   AND quota_reset_at <= CURRENT_TIMESTAMP
		 ORDER BY quota_reset_at
		 LIMIT ?
	`, max)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ResetUsedBytes zeros used_bytes and advances quota_reset_at to the 1st of
// the month after the current reset (preserving month-aligned schedule).
func (r *UserRepo) ResetUsedBytes(ctx context.Context, id int64) error {
	// Fetch current reset_at to compute next one deterministically.
	var cur sql.NullTime
	if err := r.db.QueryRowContext(ctx,
		`SELECT quota_reset_at FROM users WHERE id = ?`, id).Scan(&cur); err != nil {
		return err
	}
	base := time.Now()
	if cur.Valid {
		base = cur.Time
	}
	next := firstOfNextMonthLocal(base)
	_, err := r.db.ExecContext(ctx, `
		UPDATE users
		   SET used_bytes = 0,
		       quota_reset_at = ?
		 WHERE id = ?
	`, next, id)
	return err
}

// ----- SQL & scanning ---------------------------------------------------------

const userColumns = `
	id, username, password_hash, is_admin, is_disabled,
	created_at, last_login_at,
	disabled_until, quota_bytes, used_bytes, quota_reset_at, password_changed_at
`

var (
	selectUserByIDSQL       = `SELECT ` + userColumns + ` FROM users WHERE id = ?`
	selectUserByUsernameSQL = `SELECT ` + userColumns + ` FROM users WHERE username = ?`
	selectAllUsersSQL       = `SELECT ` + userColumns + ` FROM users ORDER BY id`
)

var (
	// ErrUsernameTaken indicates UNIQUE constraint violation on users.username.
	ErrUsernameTaken = errors.New("storage: username already taken")
)

func scanUser(s scanner) (*User, error) {
	var u User
	var isAdmin, isDisabled int
	var lastLogin, disabledUntil, quotaResetAt, passwordChangedAt sql.NullTime
	var quotaBytes sql.NullInt64
	err := s.Scan(
		&u.ID, &u.Username, &u.PasswordHash, &isAdmin, &isDisabled,
		&u.CreatedAt, &lastLogin,
		&disabledUntil, &quotaBytes, &u.UsedBytes, &quotaResetAt, &passwordChangedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	u.IsAdmin = isAdmin != 0
	u.IsDisabled = isDisabled != 0
	if lastLogin.Valid {
		u.LastLoginAt = &lastLogin.Time
	}
	if disabledUntil.Valid {
		u.DisabledUntil = &disabledUntil.Time
	}
	if quotaBytes.Valid {
		q := quotaBytes.Int64
		u.QuotaBytes = &q
	}
	if quotaResetAt.Valid {
		u.QuotaResetAt = &quotaResetAt.Time
	}
	if passwordChangedAt.Valid {
		u.PasswordChangedAt = &passwordChangedAt.Time
	}
	return &u, nil
}

// firstOfNextMonthLocal returns the first day of the month after base, at
// 00:00:00 in the server's local timezone. Ansible sets the server to
// Asia/Seoul, so this is effectively UTC+9 month boundaries (D2.25).
func firstOfNextMonthLocal(base time.Time) time.Time {
	t := base.Local()
	y, m, _ := t.Date()
	// time.Date normalizes month overflow (Dec + 1 -> next year Jan).
	return time.Date(y, m+1, 1, 0, 0, 0, 0, t.Location())
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
