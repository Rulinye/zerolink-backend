// server/usage_handlers.go — user-facing quota / usage endpoints (F14/F23).

package server

import (
	"net/http"
	"time"

	"github.com/rulinye/zerolink-backend/internal/auth"
)

// GET /api/v1/usage/me — current quota state for the authenticated user.
//
// Shape (Batch 3.3 update — D3.25):
//
//	{
//	  "used_bytes":      12345,             // total = main + room (compat)
//	  "used_bytes_main": 8000,              // sing-box / vless traffic
//	  "used_bytes_room": 4345,              // broker L3 relay traffic
//	  "quota_bytes":     107374182400,
//	  "period_start":    "2026-04-01T00:00:00+09:00",
//	  "period_end":      "2026-05-01T00:00:00+09:00"
//	}
//
// When the user has no cap set (quota_bytes is NULL in DB), we return
// quota_bytes = 0 + an additional "unlimited": true field. The client treats
// missing quota as "show a '—' placeholder".
//
// The aggregate "used_bytes" is preserved for backward compatibility with
// pre-3.3 clients; new clients should display the breakdown to help users
// diagnose where their quota is going (D3.25).
func (s *Server) handleGetMyUsage(w http.ResponseWriter, r *http.Request) {
	c := auth.FromContext(r.Context())
	u, err := s.db.Users.GetByID(r.Context(), c.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return
	}

	// period_end = quota_reset_at (what's in DB)
	// period_start = one month before that (recomputed here)
	var periodEnd time.Time
	if u.QuotaResetAt != nil {
		periodEnd = *u.QuotaResetAt
	} else {
		periodEnd = firstOfNextMonthLocal(time.Now())
	}
	periodStart := time.Date(periodEnd.Year(), periodEnd.Month()-1, 1,
		0, 0, 0, 0, periodEnd.Location())

	resp := map[string]any{
		"used_bytes":      u.TotalUsedBytes(),
		"used_bytes_main": u.UsedBytesMain,
		"used_bytes_room": u.UsedBytesRoom,
		"period_start":    periodStart.Format(time.RFC3339),
		"period_end":      periodEnd.Format(time.RFC3339),
	}
	if u.QuotaBytes != nil {
		resp["quota_bytes"] = *u.QuotaBytes
	} else {
		resp["quota_bytes"] = int64(0)
		resp["unlimited"] = true
	}
	writeJSON(w, http.StatusOK, resp)
}

// firstOfNextMonthLocal mirrors storage.firstOfNextMonthLocal; duplicated here
// to avoid an import cycle. Keeps server-local timezone semantics (Asia/Seoul
// per Ansible).
func firstOfNextMonthLocal(base time.Time) time.Time {
	t := base.Local()
	y, m, _ := t.Date()
	return time.Date(y, m+1, 1, 0, 0, 0, 0, t.Location())
}
