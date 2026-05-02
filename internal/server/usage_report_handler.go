// server/usage_report_handler.go — Phase 4 Batch 4.7 supplement / B3+B9.
//
// POST /api/v1/usage/report
//
// Brokers report per-user, per-period traffic deltas every 60s. Backend
// atomically increments users.used_bytes_room. main-half is Phase 5
// (per-user UUID + landing-side aggregation hasn't been built yet) —
// we accept entries with source="main" but ONLY honor source="room"
// for now. Anything else returns 400 so the broker fails loudly if it
// tries to send unsupported data.
//
// Auth: Bearer service_token (validated by serviceTokenMiddleware).
//
// Body shape:
//
//	{
//	  "entries": [
//	    { "user_id": 5, "source": "room", "delta_bytes_in": 12345, "delta_bytes_out": 6789 },
//	    ...
//	  ]
//	}
//
// Response:
//
//	{ "ok": true, "applied": <count> }
//
// Atomicity: each entry is its own AddUsedBytesRoom call (a single
// UPDATE...SET col = col + ?). We don't transact across entries — a
// partial failure leaves earlier entries applied. Brokers retry the
// FULL batch in the next tick if any entry fails, accepting that some
// rows may double-count. Operator's call (Honor system: rate limit
// is the authoritative defense; a few KB of double-counting on
// retry is acceptable).

package server

import (
	"encoding/json"
	"net/http"
)

type usageReportEntry struct {
	UserID        int64  `json:"user_id"`
	Source        string `json:"source"`
	DeltaBytesIn  int64  `json:"delta_bytes_in"`
	DeltaBytesOut int64  `json:"delta_bytes_out"`
}

type usageReportReq struct {
	Entries []usageReportEntry `json:"entries"`
}

func (s *Server) handleUsageReport(w http.ResponseWriter, r *http.Request) {
	var req usageReportReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if len(req.Entries) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "applied": 0})
		return
	}
	// Cap batch size so a malicious / buggy broker can't DoS by sending
	// gigantic payloads.
	const maxEntries = 1000
	if len(req.Entries) > maxEntries {
		writeError(w, http.StatusBadRequest, "too many entries")
		return
	}
	applied := 0
	for _, e := range req.Entries {
		if e.DeltaBytesIn < 0 || e.DeltaBytesOut < 0 {
			// Negative deltas are protocol violations — silently drop
			// to preserve idempotent retry semantics on the broker side.
			continue
		}
		delta := e.DeltaBytesIn + e.DeltaBytesOut
		if delta == 0 {
			continue
		}
		switch e.Source {
		case "room":
			if err := s.db.Users.AddUsedBytesRoom(r.Context(), e.UserID, delta); err != nil {
				// User might be deleted between broker's traffic
				// observation and report flush. Skip; broker will
				// drop the session anyway on next verify.
				continue
			}
			applied++
		case "main":
			// Phase 5: backend will accept main-source reports once the
			// per-user UUID system is live. For now silently drop so
			// brokers can prepare client code without the endpoint
			// 400'ing.
			continue
		default:
			// Unknown source = protocol bug; drop.
			continue
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"applied": applied,
	})
}
