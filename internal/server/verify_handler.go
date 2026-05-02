// server/verify_handler.go — Batch 3.3 Group 1c.
//
// POST /api/v1/auth/verify is the broker reverse-verify endpoint. Brokers
// call this with a Bearer service_token + a body containing the client's
// JWT to determine whether the client is currently authorized to use the
// room/relay service.
//
// Auth model:
//   - Bearer service_token (in Authorization header) -> identifies the
//     broker. Validated by serviceTokenMiddleware. Failure here is 401.
//   - body.jwt -> the user's JWT, forwarded by the broker as-is. Failures
//     here return 200 + valid:false, NOT 401, so the broker can
//     distinguish "I (broker) have a problem" from "the user has a
//     problem" without parsing error bodies.
//
// Validation chain for the user JWT (intentionally NOT including
// PasswordChangedAt or revoked_tokens — see KNOWN-ISSUES):
//   1. Parse + verify HS256 signature
//   2. Check iss matches the configured issuer
//   3. Check exp is in the future (handled by jwt library)
//   4. Look up user by uid claim
//   5. Check user is not disabled (IsEffectivelyDisabled)
//   6. Check user has not exceeded quota (used >= cap means deny)
//
// Quota check at this stage is "soft": broker calls /auth/verify when a
// client tries to JOIN a room or open a connection. Once joined, the
// broker accumulates traffic and checks quota independently via the
// G7 reporting path. So this endpoint guards admission, not enforcement.

package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/rulinye/zerolink-backend/internal/storage"
)

// --- POST /api/v1/auth/verify ----------------------------------------------

type verifyReq struct {
	JWT string `json:"jwt"`
}

// verifyResp is returned for both valid and invalid JWTs. Only "valid" is
// guaranteed present; user fields are populated only when valid=true.
type verifyResp struct {
	Valid bool `json:"valid"`

	// Reason is filled when Valid=false. Free-form short label so brokers
	// can log it; not intended for end-user display.
	Reason string `json:"reason,omitempty"`

	UserID         int64  `json:"user_id,omitempty"`
	Username       string `json:"username,omitempty"`
	IsAdmin        bool   `json:"is_admin,omitempty"`
	QuotaBytes     *int64 `json:"quota_bytes,omitempty"`     // nil = unlimited
	UsedBytes      int64  `json:"used_bytes,omitempty"`      // = main + room
	QuotaRemaining *int64 `json:"quota_remaining,omitempty"` // nil = unlimited

	// B4.7-supp / B9: per-user broker datapath rate limit (bytes/sec).
	// Broker parks this on the SessionRecord and gates outbound +
	// inbound datagrams through a token bucket. 0 means "no limit"
	// (admin set bps=0 explicitly is rejected — the field is always
	// populated to default 20 Mbps for new users via migration 0007).
	RoomRateLimitBps int64 `json:"room_rate_limit_bps,omitempty"`
}

func (s *Server) handleVerifyJWT(w http.ResponseWriter, r *http.Request) {
	// At this point serviceTokenMiddleware has already verified the broker.
	// We don't need the *ServiceToken back unless we want to log who asked,
	// but the request log already has that via req_id correlation.

	var req verifyReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.JWT == "" {
		writeError(w, http.StatusBadRequest, "jwt required")
		return
	}

	// (1) parse + verify signature, iss, exp
	claims, err := s.signer.Parse(req.JWT)
	if err != nil {
		writeJSON(w, http.StatusOK, verifyResp{
			Valid:  false,
			Reason: "jwt_invalid",
		})
		return
	}

	// (2) lookup user
	u, err := s.db.Users.GetByID(r.Context(), claims.UserID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeJSON(w, http.StatusOK, verifyResp{
				Valid:  false,
				Reason: "user_not_found",
			})
			return
		}
		writeError(w, http.StatusInternalServerError, "user lookup failed")
		return
	}

	// (3) disabled check
	if u.IsEffectivelyDisabled(time.Now()) {
		writeJSON(w, http.StatusOK, verifyResp{
			Valid:  false,
			Reason: "user_disabled",
		})
		return
	}

	// (4) quota check — combined main + room against the cap.
	used := u.TotalUsedBytes()
	if u.QuotaBytes != nil && used >= *u.QuotaBytes {
		writeJSON(w, http.StatusOK, verifyResp{
			Valid:  false,
			Reason: "quota_exceeded",
		})
		return
	}

	// All checks passed.
	resp := verifyResp{
		Valid:            true,
		UserID:           u.ID,
		Username:         u.Username,
		IsAdmin:          u.IsAdmin,
		UsedBytes:        used,
		RoomRateLimitBps: u.RoomRateLimitBps,
	}
	if u.QuotaBytes != nil {
		resp.QuotaBytes = u.QuotaBytes
		remaining := *u.QuotaBytes - used
		if remaining < 0 {
			remaining = 0
		}
		resp.QuotaRemaining = &remaining
	}
	writeJSON(w, http.StatusOK, resp)
}

// --- GET /api/v1/broker-status?short_id=KR ---------------------------------
//
// B4.7-supp / B6: per-broker enabled status. Brokers poll this every 15s
// and reject create/join requests when their own `broker_enabled` flag
// has been flipped off via the admin UI. Defense in depth alongside the
// client-side filtering of `has_broker=false` rows from
// `GET /api/v1/nodes`.
//
// Auth: Bearer service_token (validated by serviceTokenMiddleware).
//
// Query: ?short_id=<broker short id> (e.g. "KR", "GZ"). Required.
//
// Response 200:
//   { "short_id": "KR", "broker_enabled": true, "is_enabled": true }
//
// Response 404 if no node has that broker_short_id.
//
// Note: returns BOTH the per-broker `broker_enabled` operational flag
// AND the per-node `is_enabled` flag. Either one being false should
// cause the broker to reject new sessions; existing rooms continue to
// run until they naturally end (no force-disconnect on flag flip).
func (s *Server) handleBrokerStatus(w http.ResponseWriter, r *http.Request) {
	shortID := r.URL.Query().Get("short_id")
	if shortID == "" {
		writeError(w, http.StatusBadRequest, "missing short_id")
		return
	}
	n, err := s.db.Nodes.GetByBrokerShortID(r.Context(), shortID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "no broker with that short_id")
			return
		}
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"short_id":       shortID,
		"broker_enabled": n.BrokerEnabled,
		"is_enabled":     n.IsEnabled,
	})
}
