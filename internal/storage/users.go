package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// User is the persisted shape of a user row.
type User struct {
	ID           int64
	Username     string
	PasswordHash string
	IsAdmin      bool
	IsDisabled   bool
	CreatedAt    time.Time
	LastLoginAt  *time.Time
}

// UserRepo holds CRUD on the users table.
type UserRepo struct{ db *sql.DB }

// ErrNotFound is returned by Get* methods when no row matches.
var ErrNotFound = errors.New("storage: not found")

// ErrUsernameTaken is returned when Insert encounters a UNIQUE conflict.
var ErrUsernameTaken = errors.New("storage: username already taken")

// Insert creates a new user. If the username already exists the call returns
// ErrUsernameTaken (callers can treat it as a 409).
func (r *UserRepo) Insert(ctx context.Context, u *User) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO users (username, password_hash, is_admin, is_disabled)
		VALUES (?, ?, ?, ?)
	`, u.Username, u.PasswordHash, boolToInt(u.IsAdmin), boolToInt(u.IsDisabled))
	if err != nil {
		// modernc.org/sqlite returns errors with "UNIQUE constraint failed" in Error().
		if isUniqueErr(err) {
			return 0, ErrUsernameTaken
		}
		return 0, err
	}
	return res.LastInsertId()
}

// GetByUsername loads a user by username. Returns ErrNotFound if none.
func (r *UserRepo) GetByUsername(ctx context.Context, username string) (*User, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, username, password_hash, is_admin, is_disabled, created_at, last_login_at
		FROM users WHERE username = ?
	`, username)
	return scanUser(row)
}

// GetByID loads a user by id. Returns ErrNotFound if none.
func (r *UserRepo) GetByID(ctx context.Context, id int64) (*User, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, username, password_hash, is_admin, is_disabled, created_at, last_login_at
		FROM users WHERE id = ?
	`, id)
	return scanUser(row)
}

// TouchLastLogin sets last_login_at = now for the given user.
func (r *UserRepo) TouchLastLogin(ctx context.Context, id int64) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?`, id)
	return err
}

// SetDisabled toggles the disabled flag (admin operation).
func (r *UserRepo) SetDisabled(ctx context.Context, id int64, disabled bool) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE users SET is_disabled = ? WHERE id = ?`, boolToInt(disabled), id)
	return err
}

// List returns all users sorted by id.
func (r *UserRepo) List(ctx context.Context) ([]*User, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, username, password_hash, is_admin, is_disabled, created_at, last_login_at
		FROM users ORDER BY id
	`)
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

// Count returns the total number of users (used by admin-create CLI to detect
// "first run").
func (r *UserRepo) Count(ctx context.Context) (int64, error) {
	var n int64
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// scanner is satisfied by both *sql.Row and *sql.Rows.
type scanner interface{ Scan(dest ...any) error }

func scanUser(s scanner) (*User, error) {
	var u User
	var isAdmin, isDisabled int
	var lastLogin sql.NullTime
	err := s.Scan(&u.ID, &u.Username, &u.PasswordHash, &isAdmin, &isDisabled, &u.CreatedAt, &lastLogin)
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
	return &u, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
