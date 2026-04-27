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
//
// OutboundConfig (added in migration 0003 / Group 9a) is a separate
// opaque-JSON slot, also TEXT, also forwarded as-is. Keeping it
// separate from ConfigJSON lets the client distinguish "protocol
// parameters" (ConfigJSON / params) from "outbound tuning"
// (OutboundConfig / outbound_config). Defaults to "{}" so reads always
// produce well-formed JSON.
//
// Batch 3.3 additions (migration 0004): broker capability. A node may
// run a broker daemon for room rendezvous + L3 relay. BrokerEndpoint
// and BrokerShortID are nullable (nil means "this node has no broker").
// HasBroker is a denormalized convenience flag — true iff BrokerEndpoint
// is non-nil — so client UI can gate the room feature without parsing
// endpoints. Maintained at write time by the caller (typically
// import-nodes from Ansible inventory).
type Node struct {
	ID             int64
	Name           string
	Region         string
	Address        string
	Port           int
	Protocol       string
	ConfigJSON     string
	OutboundConfig string

	BrokerEndpoint *string
	BrokerShortID  *string
	HasBroker      bool
	BrokerEnabled  bool

	IsEnabled bool
	SortOrder int
	UpdatedAt time.Time
}

// NodeRepo holds CRUD on the nodes table.
type NodeRepo struct{ db *sql.DB }

// Upsert inserts a node or, if a row with the same Name exists, updates the
// mutable fields. This is the operation used by the import-nodes CLI when
// Ansible re-syncs inventory; the Name acts as the natural key.
//
// Group 9a: Upsert now also sets/updates outbound_config. Callers that
// don't have a value should set n.OutboundConfig = "{}" (the column's
// own default applies on INSERT but not on UPDATE through this path).
//
// Batch 3.3: Upsert now also writes broker_endpoint / broker_short_id /
// has_broker. Caller is responsible for keeping HasBroker consistent
// with BrokerEndpoint != nil.
func (r *NodeRepo) Upsert(ctx context.Context, n *Node) error {
	oc := n.OutboundConfig
	if oc == "" {
		oc = "{}"
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO nodes (
			name, region, address, port, protocol, config_json, outbound_config,
			broker_endpoint, broker_short_id, has_broker, broker_enabled,
			is_enabled, sort_order, updated_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(name) DO UPDATE SET
			region          = excluded.region,
			address         = excluded.address,
			port            = excluded.port,
			protocol        = excluded.protocol,
			config_json     = excluded.config_json,
			outbound_config = excluded.outbound_config,
			broker_endpoint = excluded.broker_endpoint,
			broker_short_id = excluded.broker_short_id,
			has_broker      = excluded.has_broker,
			broker_enabled  = excluded.broker_enabled,
			is_enabled      = excluded.is_enabled,
			sort_order      = excluded.sort_order,
			updated_at      = CURRENT_TIMESTAMP
	`, n.Name, n.Region, n.Address, n.Port, n.Protocol, n.ConfigJSON, oc,
		nullStr(n.BrokerEndpoint), nullStr(n.BrokerShortID), boolToInt(n.HasBroker), boolToInt(n.BrokerEnabled),
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

// nodeSelectColumns is the canonical column list for SELECT * style reads
// kept in one place so Get / GetByName / List stay in sync.
const nodeSelectColumns = `
	id, name, region, address, port, protocol, config_json, outbound_config,
	broker_endpoint, broker_short_id, has_broker, broker_enabled,
	is_enabled, sort_order, updated_at
`

// Get loads a node by id. Returns ErrNotFound if missing.
func (r *NodeRepo) Get(ctx context.Context, id int64) (*Node, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+nodeSelectColumns+` FROM nodes WHERE id = ?`, id)
	return scanNode(row)
}

// GetByName loads a node by its unique name. Returns ErrNotFound if missing.
// Used by the import-nodes CLI to detect whether an upsert would actually
// change anything, so Ansible's `changed_when` can report honestly.
func (r *NodeRepo) GetByName(ctx context.Context, name string) (*Node, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+nodeSelectColumns+` FROM nodes WHERE name = ?`, name)
	return scanNode(row)
}

// List returns nodes ordered by sort_order, name. If onlyEnabled is true,
// disabled nodes are filtered out (this is what end users see).
func (r *NodeRepo) List(ctx context.Context, onlyEnabled bool) ([]*Node, error) {
	q := `SELECT ` + nodeSelectColumns + ` FROM nodes`
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
	var enabled, hasBroker, brokerEnabled int
	var brokerEndpoint, brokerShortID sql.NullString
	err := s.Scan(&n.ID, &n.Name, &n.Region, &n.Address, &n.Port, &n.Protocol,
		&n.ConfigJSON, &n.OutboundConfig,
		&brokerEndpoint, &brokerShortID, &hasBroker, &brokerEnabled,
		&enabled, &n.SortOrder, &n.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	n.IsEnabled = enabled != 0
	n.HasBroker = hasBroker != 0
	n.BrokerEnabled = brokerEnabled != 0
	if brokerEndpoint.Valid {
		s := brokerEndpoint.String
		n.BrokerEndpoint = &s
	}
	if brokerShortID.Valid {
		s := brokerShortID.String
		n.BrokerShortID = &s
	}
	// Defensive: NOT NULL DEFAULT '{}' means this should never be empty,
	// but a manual SQL UPDATE could clear it. Keep response well-formed.
	if n.OutboundConfig == "" {
		n.OutboundConfig = "{}"
	}
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

// nullStr converts a *string to a database/sql-compatible value, mapping
// nil to a SQL NULL. Used for the broker_endpoint and broker_short_id
// columns where the empty string and NULL are distinct (NULL means
// "this node has no broker"; empty string would be a misconfiguration).
func nullStr(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

// SetBrokerEnabled toggles the broker_enabled flag for a node by ID.
// Returns ErrNotFound if the node doesn't exist.
//
// Phase 3 Batch 3.3 G4-1c-3g: lets admin temporarily disable a node's
// broker without removing the node row.
func (r *NodeRepo) SetBrokerEnabled(ctx context.Context, id int64, enabled bool) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE nodes
		   SET broker_enabled = ?,
		       updated_at     = CURRENT_TIMESTAMP
		 WHERE id = ?
	`, boolToInt(enabled), id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
