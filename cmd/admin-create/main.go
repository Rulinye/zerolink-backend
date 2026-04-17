// Command admin-create creates an admin user, prompting for the password on
// stdin. Idempotent for existing usernames only when -force is passed; the
// default refuses rather than silently rotate the password.
//
// Usage:
//
//	zerolink-backend-admin-create -db /var/lib/zerolink-backend/zerolink.db -u rulinye
//	# password prompt follows
//
// Designed for the operator to run directly over SSH:
//
//	ssh ubuntu@chuncheon
//	sudo -u zerolink /usr/local/bin/zerolink-backend-admin-create -u rulinye
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/rulinye/zerolink-backend/internal/auth"
	"github.com/rulinye/zerolink-backend/internal/storage"

	"golang.org/x/term"
)

// Version is injected at link time via -ldflags="-X main.Version=v1.2.3".
// Matches the main server binary so the Ansible role can reliably detect
// which release is installed across all three binaries.
var Version = ""

func main() {
	var (
		dbPath      = flag.String("db", "/var/lib/zerolink-backend/zerolink.db", "SQLite path")
		user        = flag.String("u", "", "username to create or update")
		force       = flag.Bool("force", false, "if user exists, reset password instead of failing")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(versionString())
		return
	}

	if *user == "" {
		fmt.Fprintln(os.Stderr, "-u username is required")
		os.Exit(2)
	}

	pw, err := readPassword()
	if err != nil {
		fmt.Fprintln(os.Stderr, "read password:", err)
		os.Exit(1)
	}
	if len(pw) < 8 {
		fmt.Fprintln(os.Stderr, "password must be >=8 chars")
		os.Exit(1)
	}

	hash, err := auth.HashPassword(pw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hash:", err)
		os.Exit(1)
	}

	db, err := storage.Open(*dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open db:", err)
		os.Exit(1)
	}
	defer db.Close()

	ctx := context.Background()
	existing, err := db.Users.GetByUsername(ctx, *user)
	switch {
	case errors.Is(err, storage.ErrNotFound):
		uid, err := db.Users.Insert(ctx, &storage.User{
			Username:     *user,
			PasswordHash: hash,
			IsAdmin:      true,
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "insert:", err)
			os.Exit(1)
		}
		fmt.Printf("created admin user %q (id=%d)\n", *user, uid)
	case err != nil:
		fmt.Fprintln(os.Stderr, "lookup:", err)
		os.Exit(1)
	default:
		if !*force {
			fmt.Fprintf(os.Stderr,
				"user %q already exists (id=%d). Re-run with -force to reset password.\n",
				existing.Username, existing.ID)
			os.Exit(1)
		}
		if _, err := db.Conn().ExecContext(ctx,
			`UPDATE users SET password_hash = ?, is_admin = 1, is_disabled = 0 WHERE id = ?`,
			hash, existing.ID); err != nil {
			fmt.Fprintln(os.Stderr, "update:", err)
			os.Exit(1)
		}
		fmt.Printf("updated admin user %q (id=%d), password reset\n",
			existing.Username, existing.ID)
	}
}

func readPassword() (string, error) {
	if term.IsTerminal(int(syscall.Stdin)) {
		fmt.Fprint(os.Stderr, "password: ")
		p1, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		fmt.Fprint(os.Stderr, "confirm:  ")
		p2, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		if string(p1) != string(p2) {
			return "", errors.New("passwords don't match")
		}
		return string(p1), nil
	}
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return "", errors.New("no input")
	}
	return strings.TrimRight(scanner.Text(), "\r\n"), nil
}

// versionString mirrors the server binary: -ldflags wins, else VCS info, else "dev".
func versionString() string {
	if Version != "" {
		return Version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" && s.Value != "" {
			rev := s.Value
			if len(rev) > 12 {
				rev = rev[:12]
			}
			return "dev-" + rev
		}
	}
	return "dev"
}
