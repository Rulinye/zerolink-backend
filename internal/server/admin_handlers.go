// server/admin_handlers.go — admin endpoints.
//
// Batch 3a additions vs Phase 1:
//   - handleAdminToggleUser accepts optional Duration (F22).
//   - handleAdminSetUserQuota (F23): POST /api/v1/admin/users/{id}/quota
//   - handleAdminSetUserPassword (F16/F17 co): POST /api/v1/admin/users/{id}/password
//   - handleAdminDeleteUser (F20): DELETE /api/v1/admin/users/{id}
//   - handleAdminCreateInvite: accepts Count + Note + ExpiresInDays (F25).
//   - handleAdminDeleteInvite (F19): DELETE /api/v1/admin/invites/{code}
//   - handleAdminExtendInvite (F25): POST /api/v1/admin/invites/{code}/extend
//
// Batch 3.3 changes (D3.25):
//   - handleAdminListUsers exposes used_bytes_main / used_bytes_room
//     breakdown alongside the aggregate used_bytes.
//   - handleAdminSetUserQuota validates the new cap against the
//     combined total (TotalUsedBytes), with a clearer error message.

package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/rulinye/zerolink-backend/internal/auth"
	"github.com/rulinye/zerolink-backend/internal/storage"
)

// --- GET /api/v1/admin/users ------------------------------------------------

func (s *Server) handleAdminListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.db.Users.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list users failed")
		return
	}
	out := make([]map[string]any, len(users))
	for i, u := range users {
		row := map[string]any{
			"id":                  u.ID,
			"username":            u.Username,
			"is_admin":            u.IsAdmin,
			"is_disabled":         u.IsEffectivelyDisabled(time.Now()),
			"created_at":          u.CreatedAt.Format(time.RFC3339),
			"used_bytes":          u.TotalUsedBytes(),
			"used_bytes_main":     u.UsedBytesMain,
			"used_bytes_room":     u.UsedBytesRoom,
			"room_rate_limit_bps": u.RoomRateLimitBps,
		}
		if u.LastLoginAt != nil {
			row["last_login_at"] = u.LastLoginAt.Format(time.RFC3339)
		}
		if u.DisabledUntil != nil {
			row["disabled_until"] = u.DisabledUntil.Format(time.RFC3339)
		}
		if u.QuotaBytes != nil {
			row["quota_bytes"] = *u.QuotaBytes
		}
		if u.QuotaResetAt != nil {
			row["quota_reset_at"] = u.QuotaResetAt.Format(time.RFC3339)
		}
		out[i] = row
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

// --- POST /api/v1/admin/users/{id}/disable (F22 — adds duration) -----------

type toggleReq struct {
	Disabled bool `json:"disabled"`
	// Duration is optional. One of: "1h", "24h", "7d", "30d", "permanent",
	// or "" (treated as "permanent"). Only honored when Disabled=true.
	Duration string `json:"duration,omitempty"`
}

var disableDurations = map[string]time.Duration{
	"1h":  time.Hour,
	"24h": 24 * time.Hour,
	"7d":  7 * 24 * time.Hour,
	"30d": 30 * 24 * time.Hour,
}

func (s *Server) handleAdminToggleUser(w http.ResponseWriter, r *http.Request) {
	c := auth.FromContext(r.Context())
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if id == c.UserID {
		writeError(w, http.StatusBadRequest, "cannot disable yourself")
		return
	}
	var req toggleReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var until *time.Time
	if req.Disabled && req.Duration != "" && req.Duration != "permanent" {
		d, ok := disableDurations[req.Duration]
		if !ok {
			writeError(w, http.StatusBadRequest,
				"invalid duration (expected one of: 1h, 24h, 7d, 30d, permanent)")
			return
		}
		t := time.Now().Add(d).UTC()
		until = &t
	}

	if err := s.db.Users.SetDisabled(r.Context(), id, req.Disabled, until); err != nil {
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}

	// When disabling, also revoke existing tokens so the target session dies
	// on its next API call (F15 co-requirement).
	if req.Disabled {
		if err := s.db.Tokens.RevokeAllForUser(r.Context(), id); err != nil {
			writeError(w, http.StatusInternalServerError, "revoke failed")
			return
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- POST /api/v1/admin/users/{id}/quota (F23) ------------------------------

type setQuotaReq struct {
	// QuotaBytes is the new cap. Pass nil to make the user unlimited.
	// Pass a non-negative int64 to set a hard cap.
	QuotaBytes *int64 `json:"quota_bytes"`
}

func (s *Server) handleAdminSetUserQuota(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var req setQuotaReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	u, err := s.db.Users.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return
	}

	if req.QuotaBytes != nil {
		if *req.QuotaBytes < 0 {
			writeError(w, http.StatusBadRequest, "quota_bytes must be >= 0")
			return
		}
		// D3.25: cap is a single combined ceiling against main + room.
		if *req.QuotaBytes < u.TotalUsedBytes() {
			writeError(w, http.StatusBadRequest,
				"new quota would be below current used_bytes (main + room)")
			return
		}
	}

	if err := s.db.Users.SetQuota(r.Context(), id, req.QuotaBytes); err != nil {
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- POST /api/v1/admin/users/{id}/password (F16: admin-assist reset) -------

type adminSetPwReq struct {
	NewPassword string `json:"new_password"`
}

func (s *Server) handleAdminSetUserPassword(w http.ResponseWriter, r *http.Request) {
	c := auth.FromContext(r.Context())
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var req adminSetPwReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.NewPassword) < 8 {
		writeError(w, http.StatusBadRequest, "new password must be at least 8 characters")
		return
	}
	if len(req.NewPassword) > 72 {
		writeError(w, http.StatusBadRequest, "new password must be at most 72 characters")
		return
	}

	hash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "hash failed")
		return
	}
	if err := s.db.Users.SetPassword(r.Context(), id, hash); err != nil {
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}
	// Revoke all sessions; target user will be kicked out on next API call.
	// (This is free: SetPassword already bumped password_changed_at.)
	_ = id
	_ = c
	w.WriteHeader(http.StatusNoContent)
}

// --- DELETE /api/v1/admin/users/{id} (F20) ----------------------------------

func (s *Server) handleAdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	c := auth.FromContext(r.Context())
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if id == c.UserID {
		writeError(w, http.StatusBadRequest, "cannot delete yourself")
		return
	}

	// Block deletion of admins as an extra safety rail. Admins must be
	// demoted via direct DB access first; prevents accidental lockout.
	u, err := s.db.Users.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	if u.IsAdmin {
		writeError(w, http.StatusForbidden, "cannot delete an admin user via API; use DB migration")
		return
	}

	_, err = s.db.ExecForCleanup("DELETE FROM users WHERE id = ?", id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- GET /api/v1/admin/invites ----------------------------------------------

func (s *Server) handleAdminListInvites(w http.ResponseWriter, r *http.Request) {
	invs, err := s.db.Invites.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list invites failed")
		return
	}
	out := make([]map[string]any, len(invs))
	for i, inv := range invs {
		row := map[string]any{
			"code":       inv.Code,
			"created_by": inv.CreatedBy,
			"created_at": inv.CreatedAt.Format(time.RFC3339),
			"expires_at": inv.ExpiresAt.Format(time.RFC3339),
			"expired":    inv.IsExpired(),
			"used":       inv.IsConsumed(),
			"note":       inv.Note,
		}
		if inv.UsedBy != nil {
			row["used_by"] = *inv.UsedBy
		}
		if inv.UsedAt != nil {
			row["used_at"] = inv.UsedAt.Format(time.RFC3339)
		}
		out[i] = row
	}
	writeJSON(w, http.StatusOK, map[string]any{"invites": out})
}

// --- POST /api/v1/admin/invites (F25 — adds note + expires_in_days) --------

type mintReq struct {
	Count int `json:"count"`
	// Note is optional; applied to all generated codes in this batch.
	Note string `json:"note,omitempty"`
	// ExpiresInDays: 7, 30, 180, 365, or 0 (=default 7). Values not in the
	// presets are rejected to keep ops simple.
	ExpiresInDays int `json:"expires_in_days,omitempty"`
}

var allowedExpiryDays = map[int]bool{0: true, 7: true, 30: true, 180: true, 365: true}

func (s *Server) handleAdminCreateInvite(w http.ResponseWriter, r *http.Request) {
	c := auth.FromContext(r.Context())
	var req mintReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Count < 1 || req.Count > 50 {
		writeError(w, http.StatusBadRequest, "count must be 1..50")
		return
	}
	if !allowedExpiryDays[req.ExpiresInDays] {
		writeError(w, http.StatusBadRequest,
			"expires_in_days must be one of: 0 (=7d default), 7, 30, 180, 365")
		return
	}
	days := req.ExpiresInDays
	if days == 0 {
		days = 7
	}

	invs, err := s.db.Invites.MintWithOptions(r.Context(), storage.MintOptions{
		Count:     req.Count,
		ExpiresIn: time.Duration(days) * 24 * time.Hour,
		Note:      req.Note,
		CreatedBy: c.UserID,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "mint failed: "+err.Error())
		return
	}

	out := make([]map[string]any, len(invs))
	for i, inv := range invs {
		out[i] = map[string]any{
			"code":       inv.Code,
			"created_by": inv.CreatedBy,
			"created_at": inv.CreatedAt.Format(time.RFC3339),
			"expires_at": inv.ExpiresAt.Format(time.RFC3339),
			"expired":    false,
			"used":       false,
			"note":       inv.Note,
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"invites": out})
}

// --- DELETE /api/v1/admin/invites/{code} (F19) ------------------------------

func (s *Server) handleAdminDeleteInvite(w http.ResponseWriter, r *http.Request) {
	code := chi.URLParam(r, "code")
	if code == "" {
		writeError(w, http.StatusBadRequest, "missing code")
		return
	}
	// Default behavior: cascade=true. Admins clicking delete intend to remove
	// the associated account (if any). To delete the invite without touching
	// the account, use ?keep_user=1.
	cascade := r.URL.Query().Get("keep_user") != "1"

	deletedUID, err := s.db.Invites.Delete(r.Context(), code, cascade)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "invite not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "delete failed: "+err.Error())
		return
	}
	resp := map[string]any{"ok": true}
	if deletedUID != nil {
		resp["deleted_user_id"] = *deletedUID
		// Also revoke tokens for the deleted user just to be thorough; the
		// DB cascade from users deletion will also remove their revoked_tokens
		// rows, but tokens in flight would still parse until middleware sees
		// the missing user row.
		_ = s.db.Tokens.RevokeAllForUser(r.Context(), *deletedUID)
	}
	writeJSON(w, http.StatusOK, resp)
}

// --- POST /api/v1/admin/invites/{code}/extend (F25) -------------------------

type extendReq struct {
	Days int `json:"days"`
}

func (s *Server) handleAdminExtendInvite(w http.ResponseWriter, r *http.Request) {
	code := chi.URLParam(r, "code")
	if code == "" {
		writeError(w, http.StatusBadRequest, "missing code")
		return
	}
	var req extendReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !allowedExpiryDays[req.Days] || req.Days == 0 {
		writeError(w, http.StatusBadRequest,
			"days must be one of: 7, 30, 180, 365")
		return
	}
	if err := s.db.Invites.Extend(r.Context(), code, time.Duration(req.Days)*24*time.Hour); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "invite not found")
			return
		}
		if errors.Is(err, storage.ErrInviteUnusable) {
			writeError(w, http.StatusConflict, "invite already used")
			return
		}
		writeError(w, http.StatusInternalServerError, "extend failed: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- GET /api/v1/admin/nodes (unchanged structurally; kept for reference) ---

func (s *Server) handleAdminListNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.db.Nodes.List(r.Context(), false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list nodes failed")
		return
	}
	out := make([]map[string]any, len(nodes))
	for i, n := range nodes {
		out[i] = map[string]any{
			"id":              n.ID,
			"name":            n.Name,
			"region":          n.Region,
			"address":         n.Address,
			"port":            n.Port,
			"protocol":        n.Protocol,
			"config_json":     n.ConfigJSON,
			"is_enabled":      n.IsEnabled,
			"sort_order":      n.SortOrder,
			"updated_at":      n.UpdatedAt.Format(time.RFC3339),
			"broker_endpoint": n.BrokerEndpoint,
			"broker_short_id": n.BrokerShortID,
			"has_broker":      n.HasBroker,
			"broker_enabled":  n.BrokerEnabled,
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": out})
}

// --- PATCH /api/v1/admin/nodes/{id}/broker (G4-1c-3g) ---
//
// Toggle the broker_enabled flag for a node. Only meaningful when the
// node also has has_broker=1; if has_broker=0, the toggle is a no-op
// from the client's perspective (the broker fields are hidden either
// way).
//
// Request body: { "enabled": bool }
// Response: { "ok": true, "broker_enabled": bool }
func (s *Server) handleAdminToggleBroker(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid node id")
		return
	}

	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}

	if err := s.db.Nodes.SetBrokerEnabled(r.Context(), id, body.Enabled); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "node not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"broker_enabled": body.Enabled,
	})
}

// --- B4.7-supp / B9: PATCH /api/v1/admin/users/{id}/rate-limit -----------
//
// Per-user broker datapath rate limit. Body: { "bps": int }.
// Validation:
//   - bps > 0
//   - bps < MainRateLimitCeilingBps (50 Mbps == 6,250,000 bytes/sec)
//
// The MainRateLimitCeiling is hardcoded until Phase 5 promotes it to
// a separate column (and a corresponding admin endpoint). Operator
// surfaced the constraint: "联机限速一定要低于主连接限速,否则提示
// 不生效". Until per-user main rate limits exist, this is the
// effective ceiling.

const MainRateLimitCeilingBps = int64(6_250_000) // 50 Mbps in bytes/sec

type setRateLimitReq struct {
	Bps int64 `json:"bps"`
}

func (s *Server) handleAdminSetUserRateLimit(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var req setRateLimitReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Bps <= 0 {
		writeError(w, http.StatusBadRequest, "bps must be > 0")
		return
	}
	if req.Bps >= MainRateLimitCeilingBps {
		writeError(w, http.StatusBadRequest,
			"联机限速必须低于主连接限速 (50 Mbps = 6250000 bytes/sec)")
		return
	}
	// Confirm user exists for cleaner 404 vs 500.
	if _, err := s.db.Users.GetByID(r.Context(), id); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	if err := s.db.Users.SetRoomRateLimit(r.Context(), id, req.Bps); err != nil {
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                  true,
		"room_rate_limit_bps": req.Bps,
	})
}

// --- B4.7-supp / B3+B9 admin half: GET /api/v1/admin/usage/audit --------
//
// Returns current-period traffic totals + caps for all users in one
// call so the admin "流量审计" page can render a single-screen
// snapshot. No historical drill-down — that's Phase 5 (would need
// the traffic detail table to be populated by per-period
// aggregation, which the current room-half writes to users.* and
// not to traffic.*).
//
// Rows include both source halves (main + room) so the UI can show
// "main 待 Phase 5 启用" with current 0 values explicitly.
func (s *Server) handleAdminUsageAudit(w http.ResponseWriter, r *http.Request) {
	users, err := s.db.Users.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		return
	}
	out := make([]map[string]any, 0, len(users))
	now := time.Now()
	for _, u := range users {
		if u.IsEffectivelyDisabled(now) {
			// Hide disabled users from audit by default; admin can
			// still find them via the regular user list.
			continue
		}
		row := map[string]any{
			"user_id":             u.ID,
			"username":            u.Username,
			"used_bytes_main":     u.UsedBytesMain,
			"used_bytes_room":     u.UsedBytesRoom,
			"used_bytes":          u.TotalUsedBytes(),
			"room_rate_limit_bps": u.RoomRateLimitBps,
		}
		if u.QuotaBytes != nil {
			row["quota_bytes"] = *u.QuotaBytes
		}
		if u.QuotaResetAt != nil {
			row["period_end"] = u.QuotaResetAt.Format(time.RFC3339)
		}
		out = append(out, row)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"users":                       out,
		"main_rate_limit_ceiling_bps": MainRateLimitCeilingBps,
		"main_traffic_status":         "phase5_pending",
	})
}
