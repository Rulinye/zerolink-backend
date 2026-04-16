package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Node is a server entry the client can connect to. The bulk of the
// protocol-specific configuration lives in ConfigJSON; that field is opaque
// to the backend and forwarded as-is to the client (or rendered into Clash YAML).
type Node struct {
	ID         int64
	Name       string
	Region     string
	Address    string
	Port       int
	Protocol   string
	ConfigJSON string
	IsEnabled  bool
	SortOrder  int
	UpdatedAt  time.Time
}

// NodeRepo holds CRUD on the nodes table.
type NodeRepo struct{ db *sql.DB }

// Upsert inserts a node or, if a row with the same Name exists, updates the
// mutable fields. This is the operation used by the import-nodes CLI when
// Ansible re-syncs inventory; the Name acts as the natural key.
func (r *NodeRepo) Upsert(ctx context.Context, n *Node) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO nodes (name, region, address, port, protocol, config_json, is_enabled, sort_order, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(name) DO UPDATE SET
			region      = excluded.region,
			address     = excluded.address,
			port        = excluded.port,
			protocol    = excluded.protocol,
			config_json = excluded.config_json,
			is_enabled  = excluded.is_enabled,
			sort_order  = excluded.sort_order,
			updated_at  = CURRENT_TIMESTAMP
	`, n.Name, n.Region, n.Address, n.Port, n.Protocol, n.ConfigJSON,
		boolToInt(n.IsEnabled), n.SortOrder)
	return err
}

// DeleteMissing removes any node whose Name is NOT in keepNames. Used by
// import-nodes to prune nodes that have been removed from inventory.
// Returns the number of rows deleted.
func (r *NodeRepo) DeleteMissing(ctx context.Context, keepNames []string) (int64, error) {
	if len(keepNames) == 0 {
		// Refuse to delete everything by accident; the caller almost
		// certainly passed an empty slice due to a bug.
		return 0, errors.New("storage: refusing to delete all nodes (keepNames is empty)")
	}
	// Build the IN clause manually because database/sql doesn't expand slices.
	q := `DELETE FROM nodes WHERE name NOT IN (?` +
		repeatComma(len(keepNames)-1) + `)`
	args := make([]any, len(keepNames))
	for i, n := range keepNames {
		args[i] = n
	}
	res, err := r.db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Get loads a node by id. Returns ErrNotFound if missing.
func (r *NodeRepo) Get(ctx context.Context, id int64) (*Node, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, name, region, address, port, protocol, config_json,
		       is_enabled, sort_order, updated_at
		FROM nodes WHERE id = ?
	`, id)
	return scanNode(row)
}

// List returns nodes ordered by sort_order, name. If onlyEnabled is true,
// disabled nodes are filtered out (this is what end users see).
func (r *NodeRepo) List(ctx context.Context, onlyEnabled bool) ([]*Node, error) {
	q := `SELECT id, name, region, address, port, protocol, config_json,
	             is_enabled, sort_order, updated_at FROM nodes`
	if onlyEnabled {
		q += ` WHERE is_enabled = 1`
	}
	q += ` ORDER BY sort_order, name`
	rows, err := r.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func scanNode(s scanner) (*Node, error) {
	var n Node
	var enabled int
	err := s.Scan(&n.ID, &n.Name, &n.Region, &n.Address, &n.Port, &n.Protocol,
		&n.ConfigJSON, &enabled, &n.SortOrder, &n.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	n.IsEnabled = enabled != 0
	return &n, nil
}

func repeatComma(n int) string {
	if n <= 0 {
		return ""
	}
	out := make([]byte, 0, n*2)
	for i := 0; i < n; i++ {
		out = append(out, ',', '?')
	}
	return string(out)
}
