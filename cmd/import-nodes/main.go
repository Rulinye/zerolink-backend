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
//
// Usage from Ansible:
//
//   - copy: src=nodes.json dest=/etc/zerolink-backend/nodes.json
//   - command: /usr/local/bin/zerolink-backend-import-nodes -db /var/lib/zerolink-backend/zerolink.db -in /etc/zerolink-backend/nodes.json
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/rulinye/zerolink-backend/internal/storage"
)

type entry struct {
	Name      string         `json:"name"`
	Region    string         `json:"region"`
	Address   string         `json:"address"`
	Port      int            `json:"port"`
	Protocol  string         `json:"protocol"`
	Config    map[string]any `json:"config"`
	Enabled   *bool          `json:"enabled"` // pointer so default = enabled
	SortOrder int            `json:"sort_order"`
}

func main() {
	var (
		dbPath = flag.String("db", "/var/lib/zerolink-backend/zerolink.db", "SQLite path")
		inPath = flag.String("in", "", "path to nodes.json")
		dryRun = flag.Bool("dry-run", false, "print plan, do not modify DB")
	)
	flag.Parse()

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
		keep := make([]string, len(entries))
		for i, e := range entries {
			fmt.Printf("  + %s (%s:%d %s)\n", e.Name, e.Address, e.Port, e.Protocol)
			keep[i] = e.Name
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
	keep := make([]string, 0, len(entries))
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
		err = db.Nodes.Upsert(ctx, &storage.Node{
			Name:       e.Name,
			Region:     e.Region,
			Address:    e.Address,
			Port:       e.Port,
			Protocol:   e.Protocol,
			ConfigJSON: string(cfgJSON),
			IsEnabled:  enabled,
			SortOrder:  sortOrder,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "upsert %s: %v\n", e.Name, err)
			os.Exit(1)
		}
		keep = append(keep, e.Name)
	}

	deleted, err := db.Nodes.DeleteMissing(ctx, keep)
	if err != nil {
		fmt.Fprintln(os.Stderr, "delete missing:", err)
		os.Exit(1)
	}
	fmt.Printf("import-nodes: upserted=%d deleted=%d\n", len(keep), deleted)
}
