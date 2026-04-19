// Package main — admin-create CLI.
//
// Usage:
//
//   # Create a new admin user:
//   zerolink-backend-admin-create -u alice
//       (prompts for password twice)
//
//   # Reset password for an EXISTING user (admin or not) — F16:
//   zerolink-backend-admin-create -u rulinye --reset-password
//       (prompts for new password twice)
//
// With --reset-password, the user must already exist. Otherwise the CLI errors
// out instead of silently creating a new user (which would be confusing if
// the admin just mistyped the username).

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"golang.org/x/term"

	"github.com/rulinye/zerolink-backend/internal/auth"
	"github.com/rulinye/zerolink-backend/internal/config"
	"github.com/rulinye/zerolink-backend/internal/storage"
)

func main() {
	var (
		username      = flag.String("u", "", "username to create or reset")
		resetPassword = flag.Bool("reset-password", false, "reset password for existing user (no new user created)")
		makeAdmin     = flag.Bool("admin", true, "grant admin to newly-created user (ignored with --reset-password)")
	)
	flag.Parse()

	if *username == "" {
		fmt.Fprintln(os.Stderr, "usage: zerolink-backend-admin-create -u <username> [--reset-password] [--admin=false]")
		os.Exit(2)
	}

	cfg, err := config.Load()
	if err != nil {
		fatal("config: %v", err)
	}

	db, err := storage.Open(cfg.DBPath)
	if err != nil {
		fatal("open db: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	if *resetPassword {
		resetPasswordFlow(ctx, db, *username)
		return
	}
	createUserFlow(ctx, db, *username, *makeAdmin)
}

func createUserFlow(ctx context.Context, db *storage.DB, username string, admin bool) {
	// Reject if already exists.
	if _, err := db.Users.GetByUsername(ctx, username); err == nil {
		fatal("user %q already exists (use --reset-password to change its password)", username)
	} else if !errors.Is(err, storage.ErrNotFound) {
		fatal("lookup: %v", err)
	}

	pw := promptNewPassword()
	hash, err := auth.HashPassword(pw)
	if err != nil {
		fatal("hash: %v", err)
	}
	u, err := db.Users.Create(ctx, username, hash, admin)
	if err != nil {
		fatal("create: %v", err)
	}
	fmt.Printf("created user %q (id=%d, admin=%v)\n", u.Username, u.ID, u.IsAdmin)
}

func resetPasswordFlow(ctx context.Context, db *storage.DB, username string) {
	u, err := db.Users.GetByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			fatal("user %q does not exist", username)
		}
		fatal("lookup: %v", err)
	}

	pw := promptNewPassword()
	hash, err := auth.HashPassword(pw)
	if err != nil {
		fatal("hash: %v", err)
	}
	if err := db.Users.SetPassword(ctx, u.ID, hash); err != nil {
		fatal("update: %v", err)
	}
	// SetPassword bumps password_changed_at, which invalidates all existing
	// JWTs for this user. Target user will see a hard-kickout modal on their
	// next heartbeat (D2.24).
	fmt.Printf("password reset for %q (id=%d); all existing sessions invalidated\n",
		u.Username, u.ID)
}

// promptNewPassword asks for the password twice and returns it plaintext.
// Terminal echo is disabled while typing.
func promptNewPassword() string {
	fmt.Fprint(os.Stderr, "new password: ")
	pw1, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		fatal("read password: %v", err)
	}
	if len(pw1) < 8 {
		fatal("password too short (need >=8 chars)")
	}
	if len(pw1) > 72 {
		fatal("password too long (bcrypt limit 72 bytes)")
	}

	fmt.Fprint(os.Stderr, "confirm password: ")
	pw2, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		fatal("read password: %v", err)
	}
	if string(pw1) != string(pw2) {
		fatal("passwords do not match")
	}
	return string(pw1)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "admin-create: "+format+"\n", args...)
	os.Exit(1)
}
