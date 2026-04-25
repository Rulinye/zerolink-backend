// Package main — gen-service-token CLI.
//
// Generates a new service token for an internal-service caller (currently:
// broker daemons) and prints the plaintext to stdout. The plaintext is
// shown EXACTLY ONCE; backend stores only sha256(plaintext). After this
// command exits, recovering the plaintext requires regenerating + rotating.
//
// Usage:
//
//   # Provision a token for the chuncheon (KR) broker:
//   ZL_DB_PATH=/var/lib/zerolink-backend/zerolink.db \
//     zerolink-backend-gen-service-token -label broker-kr
//
//   # List existing tokens (without revealing plaintext):
//   ZL_DB_PATH=... zerolink-backend-gen-service-token -list
//
//   # Disable an existing token (rotation: provision new, deploy, verify,
//   # then disable old):
//   ZL_DB_PATH=... zerolink-backend-gen-service-token -disable broker-kr
//
// The generated token must be pasted into the Ansible vault (typically
// secrets/vault.yml) under a key like vault_broker_service_token_kr, then
// referenced from broker host_vars. See roles/broker/ in the infra repo
// (Group 3 / G3 of Batch 3.3).
//
// Exit codes:
//   0 — success
//   1 — runtime failure (DB open, generation, etc.)
//   2 — usage error (missing flags)

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/rulinye/zerolink-backend/internal/config"
	"github.com/rulinye/zerolink-backend/internal/storage"
)

// Version is injected at link time. Kept for parity with the other CLIs so
// the Ansible per-binary version detection works on this binary too.
var Version = ""

func main() {
	var (
		showVersion bool
		label       string
		list        bool
		disable     string
	)
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.StringVar(&label, "label", "",
		"create a new service token with this label (e.g. broker-kr)")
	flag.BoolVar(&list, "list", false,
		"list all service tokens (label, created_at, last_used_at, disabled)")
	flag.StringVar(&disable, "disable", "",
		"disable an existing service token by label (irreversible until manual SQL)")
	flag.Parse()

	if showVersion {
		fmt.Println(versionString())
		return
	}

	// Exactly one mode flag must be set.
	modes := 0
	if label != "" {
		modes++
	}
	if list {
		modes++
	}
	if disable != "" {
		modes++
	}
	if modes != 1 {
		fmt.Fprintln(os.Stderr,
			"usage: zerolink-backend-gen-service-token [-label NAME | -list | -disable NAME]")
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

	switch {
	case label != "":
		createFlow(ctx, db, label)
	case list:
		listFlow(ctx, db)
	case disable != "":
		disableFlow(ctx, db, disable)
	}
}

func createFlow(ctx context.Context, db *storage.DB, label string) {
	plaintext, err := db.ServiceTokens.Create(ctx, label)
	if err != nil {
		fatal("create: %v", err)
	}
	// Plaintext to stdout (machine-consumable); diagnostic to stderr so
	// `... | ansible-vault encrypt_string` works without scraping.
	fmt.Fprintf(os.Stderr,
		"service token created (label=%q). Paste the plaintext below into "+
			"the Ansible vault — it will NOT be shown again.\n", label)
	fmt.Println(plaintext)
}

func listFlow(ctx context.Context, db *storage.DB) {
	tokens, err := db.ServiceTokens.List(ctx)
	if err != nil {
		fatal("list: %v", err)
	}
	if len(tokens) == 0 {
		fmt.Fprintln(os.Stderr, "(no service tokens)")
		return
	}
	fmt.Printf("%-24s %-20s %-20s %s\n", "LABEL", "CREATED", "LAST_USED", "STATUS")
	for _, t := range tokens {
		lastUsed := "-"
		if t.LastUsedAt != nil {
			lastUsed = t.LastUsedAt.Format("2006-01-02 15:04:05")
		}
		status := "active"
		if t.Disabled {
			status = "disabled"
		}
		fmt.Printf("%-24s %-20s %-20s %s\n",
			t.Label,
			t.CreatedAt.Format("2006-01-02 15:04:05"),
			lastUsed,
			status,
		)
	}
}

func disableFlow(ctx context.Context, db *storage.DB, label string) {
	if err := db.ServiceTokens.Disable(ctx, label); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			fatal("no service token with label %q", label)
		}
		fatal("disable: %v", err)
	}
	fmt.Fprintf(os.Stderr, "service token %q disabled.\n", label)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "gen-service-token: "+format+"\n", args...)
	os.Exit(1)
}

// versionString mirrors main.go's version logic. Kept simple — this binary
// doesn't use VCS-info fallback because it's a CLI; if Version is unset,
// "dev" is fine.
func versionString() string {
	if Version != "" {
		return Version
	}
	return "dev"
}
