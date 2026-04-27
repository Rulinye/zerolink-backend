// Command import-nodes syncs the nodes table from a JSON file produced by
// Ansible (templated from inventory). The JSON shape is an array of:
//
//	{
//	  "name":     "chuncheon-01",
//	  "region":   "kr-chuncheon",
//	  "address":  "gz.example.com",
//	  "port":     23456,
//	  "protocol": "vless+reality",
//	  "config":   { ... arbitrary client params, embedded as-is into config_json ... },
//	  "enabled":  true,
//	  "sort_order": 100
//	}
//
// The tool upserts every entry by `name` and deletes any node whose name is
// not in the file (per phase-1-handover §8.3: source of truth is inventory).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime/debug"

	"github.com/rulinye/zerolink-backend/internal/storage"
)

// Version is injected at link time via -ldflags="-X main.Version=v1.2.3".
var Version = ""

type entry struct {
	Name      string         `json:"name"`
	Region    string         `json:"region"`
	Address   string         `json:"address"`
	Port      int            `json:"port"`
	Protocol  string         `json:"protocol"`
	Config    map[string]any `json:"config"`
	Enabled   *bool          `json:"enabled"`
	SortOrder int            `json:"sort_order"`

	// Batch 3.3 G4-1a-2: optional broker fields. nil/empty when this
	// node has no broker daemon; HasBroker is false in that case.
	BrokerEndpoint *string `json:"broker_endpoint,omitempty"`
	BrokerShortID  *string `json:"broker_short_id,omitempty"`
	HasBroker      bool    `json:"has_broker,omitempty"`

	// Batch 3.3 G4-1c-3g: per-node broker_enabled toggle. Nullable
	// pointer so we can distinguish "inventory said nothing" (nil,
	// follow HasBroker) from "inventory said false" (explicit
	// disable). When nil, defaults to HasBroker — i.e. having a
	// broker daemon implies advertising it unless explicitly
	// disabled.
	BrokerEnabled *bool `json:"broker_enabled,omitempty"`
}

func main() {
	var (
		dbPath      = flag.String("db", "/var/lib/zerolink-backend/zerolink.db", "SQLite path")
		inPath      = flag.String("in", "", "path to nodes.json")
		dryRun      = flag.Bool("dry-run", false, "print plan, do not modify DB")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(versionString())
		return
	}

	if *inPath == "" {
		fmt.Fprintln(os.Stderr, "-in is required")
		os.Exit(2)
	}

	raw, err := os.ReadFile(*inPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read input:", err)
		os.Exit(1)
	}

	var entries []entry
	if err := json.Unmarshal(raw, &entries); err != nil {
		fmt.Fprintln(os.Stderr, "parse json:", err)
		os.Exit(1)
	}

	if len(entries) == 0 {
		fmt.Fprintln(os.Stderr, "refusing: no nodes in input file")
		os.Exit(1)
	}

	for i, e := range entries {
		if e.Name == "" || e.Address == "" || e.Port == 0 || e.Protocol == "" {
			fmt.Fprintf(os.Stderr, "entry #%d invalid: name/address/port/protocol required\n", i)
			os.Exit(1)
		}
	}

	if *dryRun {
		fmt.Println("DRY RUN. Would upsert:")
		for _, e := range entries {
			fmt.Printf("  + %s (%s:%d %s)\n", e.Name, e.Address, e.Port, e.Protocol)
		}
		fmt.Println("Would delete any node not in the list above.")
		return
	}

	db, err := storage.Open(*dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open db:", err)
		os.Exit(1)
	}
	defer db.Close()

	ctx := context.Background()

	// Count rows that actually change so the tool can report accurately.
	// This lets the Ansible role's changed_when reflect reality.
	upsertedChanged := 0
	for _, e := range entries {
		cfgJSON, err := json.Marshal(e.Config)
		if err != nil {
			fmt.Fprintf(os.Stderr, "marshal config for %s: %v\n", e.Name, err)
			os.Exit(1)
		}
		enabled := true
		if e.Enabled != nil {
			enabled = *e.Enabled
		}
		sortOrder := e.SortOrder
		if sortOrder == 0 {
			sortOrder = 100
		}

		// Compare against existing row; only count as changed if fields differ.
		existing, err := db.Nodes.GetByName(ctx, e.Name)
		changed := true
		if err == nil && existing != nil {
			changed = existing.Address != e.Address ||
				existing.Port != e.Port ||
				existing.Region != e.Region ||
				existing.Protocol != e.Protocol ||
				existing.ConfigJSON != string(cfgJSON) ||
				existing.IsEnabled != enabled ||
				existing.SortOrder != sortOrder ||
				ptrStrNotEqual(existing.BrokerEndpoint, e.BrokerEndpoint) ||
				ptrStrNotEqual(existing.BrokerShortID, e.BrokerShortID) ||
				existing.HasBroker != e.HasBroker
		}

		err = db.Nodes.Upsert(ctx, &storage.Node{
			Name:       e.Name,
			Region:     e.Region,
			Address:    e.Address,
			Port:       e.Port,
			Protocol:   e.Protocol,
			ConfigJSON: string(cfgJSON),
			IsEnabled:  enabled,
			SortOrder:  sortOrder,

			BrokerEndpoint: e.BrokerEndpoint,
			BrokerShortID:  e.BrokerShortID,
			HasBroker:      e.HasBroker,
			BrokerEnabled:  resolveBrokerEnabled(e.BrokerEnabled, e.HasBroker),
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "upsert %s: %v\n", e.Name, err)
			os.Exit(1)
		}
		if changed {
			upsertedChanged++
		}
	}

	keep := make([]string, 0, len(entries))
	for _, e := range entries {
		keep = append(keep, e.Name)
	}
	deleted, err := db.Nodes.DeleteMissing(ctx, keep)
	if err != nil {
		fmt.Fprintln(os.Stderr, "delete missing:", err)
		os.Exit(1)
	}
	fmt.Printf("import-nodes: upserted=%d deleted=%d\n", upsertedChanged, deleted)
}

// ptrStrNotEqual compares two *string for inequality, treating nil and ""
// as equivalent (both "absent"). Used by the changed-detection logic.
func ptrStrNotEqual(a, b *string) bool {
	av, bv := "", ""
	if a != nil {
		av = *a
	}
	if b != nil {
		bv = *b
	}
	return av != bv
}

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

// resolveBrokerEnabled determines the broker_enabled flag from the
// inventory's optional override and the physical has_broker capability.
// Inventory absent (nil) -> follow has_broker (i.e. having a broker
// implies advertising it). Inventory explicit -> use the explicit
// value. This keeps existing inventories that pre-date G4-1c-3g
// working without breakage.
func resolveBrokerEnabled(override *bool, hasBroker bool) bool {
	if override != nil {
		return *override
	}
	return hasBroker
}
