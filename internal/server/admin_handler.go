package server

import (
	"crypto/rand"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/rulinye/zerolink-backend/internal/auth"
	"github.com/rulinye/zerolink-backend/internal/storage"
)

// --- GET /api/v1/admin/users ----------------------------------------------

func (s *Server) handleAdminListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.db.Users.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list users failed")
		return
	}
	out := make([]map[string]any, len(users))
	for i, u := range users {
		row := map[string]any{
			"id":          u.ID,
			"username":    u.Username,
			"is_admin":    u.IsAdmin,
			"is_disabled": u.IsDisabled,
			"created_at":  u.CreatedAt.Format(time.RFC3339),
		}
		if u.LastLoginAt != nil {
			row["last_login_at"] = u.LastLoginAt.Format(time.RFC3339)
		}
		out[i] = row
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

// --- POST /api/v1/admin/users/{id}/disable --------------------------------

type toggleReq struct {
	Disabled bool `json:"disabled"`
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
	if err := s.db.Users.SetDisabled(r.Context(), id, req.Disabled); err != nil {
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// --- GET /api/v1/admin/invites --------------------------------------------

func (s *Server) handleAdminListInvites(w http.ResponseWriter, r *http.Request) {
	onlyUnused := r.URL.Query().Get("unused") == "true"
	invs, err := s.db.Invites.List(r.Context(), onlyUnused)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		return
	}
	out := make([]map[string]any, len(invs))
	for i, in := range invs {
		row := map[string]any{
			"code":       in.Code,
			"created_by": in.CreatedBy,
			"created_at": in.CreatedAt.Format(time.RFC3339),
			"expires_at": in.ExpiresAt.Format(time.RFC3339),
			"note":       in.Note,
			"used":       in.IsConsumed(),
			"expired":    in.IsExpired(),
		}
		if in.UsedBy != nil {
			row["used_by"] = *in.UsedBy
		}
		if in.UsedAt != nil {
			row["used_at"] = in.UsedAt.Format(time.RFC3339)
		}
		out[i] = row
	}
	writeJSON(w, http.StatusOK, map[string]any{"invites": out})
}

// --- POST /api/v1/admin/invites -------------------------------------------

type createInviteReq struct {
	Note     string `json:"note"`
	TTLHours int    `json:"ttl_hours"`
	Count    int    `json:"count"`
}

func (s *Server) handleAdminCreateInvite(w http.ResponseWriter, r *http.Request) {
	c := auth.FromContext(r.Context())
	var req createInviteReq
	// Allow empty body; fall back to defaults.
	if r.ContentLength > 0 {
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if req.TTLHours <= 0 {
		req.TTLHours = 24 * 7 // 7 days, per phase-1-handover §3.4
	}
	if req.TTLHours > 24*30 {
		writeError(w, http.StatusBadRequest, "ttl_hours must be <= 720")
		return
	}
	if req.Count <= 0 {
		req.Count = 1
	}
	if req.Count > 50 {
		writeError(w, http.StatusBadRequest, "count must be <= 50")
		return
	}

	created := make([]map[string]any, 0, req.Count)
	for i := 0; i < req.Count; i++ {
		code, err := newInviteCode()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "code generation failed")
			return
		}
		exp := time.Now().Add(time.Duration(req.TTLHours) * time.Hour)
		if err := s.db.Invites.Insert(r.Context(), &storage.Invite{
			Code:      code,
			CreatedBy: c.UserID,
			ExpiresAt: exp,
			Note:      req.Note,
		}); err != nil {
			// Code collision is essentially impossible with 8 random chars
			// in a 32-char alphabet (32^8 = 2^40), but the repo handles it
			// by returning an error string we can surface as a retry hint.
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		created = append(created, map[string]any{
			"code":       code,
			"expires_at": exp.Format(time.RFC3339),
		})
	}
	writeJSON(w, http.StatusCreated, map[string]any{"invites": created})
}

// --- GET /api/v1/admin/nodes (full view, including config_json) -----------

func (s *Server) handleAdminListNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.db.Nodes.List(r.Context(), false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		return
	}
	out := make([]map[string]any, len(nodes))
	for i, n := range nodes {
		out[i] = map[string]any{
			"id":          n.ID,
			"name":        n.Name,
			"region":      n.Region,
			"address":     n.Address,
			"port":        n.Port,
			"protocol":    n.Protocol,
			"config_json": n.ConfigJSON,
			"is_enabled":  n.IsEnabled,
			"sort_order":  n.SortOrder,
			"updated_at":  n.UpdatedAt.Format(time.RFC3339),
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": out})
}

// --- helpers --------------------------------------------------------------

// newInviteCode creates a human-readable invite code per phase-1-handover §3.4
// (option B: short, easy to type). Format: AAAA-BBBB (8 base32 chars + dash).
// Crockford base32 (no I/L/O/U) to avoid visually ambiguous characters.
func newInviteCode() (string, error) {
	const alphabet = "ABCDEFGHJKMNPQRSTVWXYZ23456789"
	const codeLen = 8 // 30^8 ≈ 2^39 — plenty for an admin-generated code list
	b := make([]byte, codeLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, codeLen+1)
	for i := 0; i < codeLen; i++ {
		out[i] = alphabet[int(b[i])%len(alphabet)]
		if i == 3 {
			out[i+1] = '-'
		}
	}
	// Re-layout into XXXX-XXXX.
	final := make([]byte, 9)
	copy(final[0:4], out[0:4])
	final[4] = '-'
	copy(final[5:9], out[4:8])
	return string(final), nil
}
