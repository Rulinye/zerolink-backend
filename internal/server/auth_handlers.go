// server/auth_handlers.go — auth-flow HTTP handlers.
//
// Batch 3a changes:
//   - handleLogin now calls tokens.RevokeAllForUser (= bump password_changed_at)
//     BEFORE issuing the new JWT. This implements single-device login: any
//     previously-issued token becomes stale (iat < password_changed_at) and
//     the middleware will reject it on next use. The user whose device just
//     got "kicked" sees a hard-kickout modal via the heartbeat (D2.24).
//   - handleChangePassword is new (F17). Verifies current password, updates
//     hash, bumps password_changed_at (which double-serves as "revoke all
//     existing tokens"), then issues a fresh JWT so the caller stays logged in.

package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/rulinye/zerolink-backend/internal/auth"
	"github.com/rulinye/zerolink-backend/internal/storage"
)

// --- POST /api/v1/auth/login ------------------------------------------------

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type authResp struct {
	UserID    int64  `json:"user_id"`
	Username  string `json:"username"`
	Token     string `json:"token"`
	IsAdmin   bool   `json:"is_admin"`
	ExpiresAt int64  `json:"expires_at"` // unix seconds
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "username and password required")
		return
	}

	u, err := s.db.Users.GetByUsername(r.Context(), req.Username)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	if u.IsEffectivelyDisabled(time.Now()) {
		// Expose a distinct status so the client can show "account disabled"
		// specifically (D2.24).
		writeError(w, http.StatusForbidden, "account disabled")
		return
	}
	if err := auth.CheckPassword(u.PasswordHash, req.Password); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	// Invalidate all previously-issued tokens for this user (F15 single-device
	// login semantic). This is done BEFORE issuing the new token so the
	// "password_changed_at > new_iat" race can't happen.
	if err := s.db.Tokens.RevokeAllForUser(r.Context(), u.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "revoke-previous failed")
		return
	}

	// Issue fresh JWT.
	tok, claims, err := s.signer.Issue(u.ID, u.Username, u.IsAdmin)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token issue failed")
		return
	}

	// Update last_login_at (best-effort; don't fail the request).
	_ = s.db.Users.UpdateLastLogin(r.Context(), u.ID)

	writeJSON(w, http.StatusOK, authResp{
		UserID:    u.ID,
		Username:  u.Username,
		Token:     tok,
		IsAdmin:   u.IsAdmin,
		ExpiresAt: claims.ExpiresAt.Unix(),
	})
}

// --- POST /api/v1/auth/register ---------------------------------------------

type registerReq struct {
	InviteCode string `json:"invite_code"`
	Username   string `json:"username"`
	Password   string `json:"password"`
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.InviteCode == "" || req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "invite_code, username, password required")
		return
	}
	if len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}
	if len(req.Password) > 72 {
		writeError(w, http.StatusBadRequest, "password must be at most 72 characters")
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "password hash failed")
		return
	}

	// Transaction not wrapped here; rely on invites.Consume being idempotent-
	// on-race (unique constraint on used_by, conditional UPDATE).
	user, err := s.db.Users.Create(r.Context(), req.Username, hash, false)
	if err != nil {
		if errors.Is(err, storage.ErrUsernameTaken) {
			writeError(w, http.StatusConflict, "username already taken")
			return
		}
		writeError(w, http.StatusInternalServerError, "create user failed")
		return
	}
	if err := s.db.Invites.Consume(r.Context(), req.InviteCode, user.ID); err != nil {
		// Roll back: delete the just-created user. Best effort; log and
		// continue so we can still return a meaningful error.
		_, _ = s.db.Invites.Delete(r.Context(), "__noop__", false) // no-op to keep symmetry
		_ = s.rollbackUser(user.ID)
		if errors.Is(err, storage.ErrInviteUnusable) {
			writeError(w, http.StatusBadRequest, "invite code invalid, used, or expired")
			return
		}
		writeError(w, http.StatusInternalServerError, "consume invite failed")
		return
	}

	tok, claims, err := s.signer.Issue(user.ID, user.Username, user.IsAdmin)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token issue failed")
		return
	}
	_ = s.db.Users.UpdateLastLogin(r.Context(), user.ID)

	writeJSON(w, http.StatusOK, authResp{
		UserID:    user.ID,
		Username:  user.Username,
		Token:     tok,
		IsAdmin:   user.IsAdmin,
		ExpiresAt: claims.ExpiresAt.Unix(),
	})
}

// rollbackUser drops a newly-created user (used when invite consumption fails
// after user row was inserted). Swallows error; best-effort cleanup.
func (s *Server) rollbackUser(id int64) error {
	// Avoid leaking partial state. No dedicated repo method — use raw DB.
	_, err := s.db.ExecForCleanup("DELETE FROM users WHERE id = ?", id)
	return err
}

// --- GET /api/v1/auth/me ----------------------------------------------------

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	c := auth.FromContext(r.Context())
	u, err := s.db.Users.GetByID(r.Context(), c.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":    u.ID,
		"username":   u.Username,
		"is_admin":   u.IsAdmin,
		"created_at": u.CreatedAt.Format(time.RFC3339),
	})
}

// --- POST /api/v1/auth/logout -----------------------------------------------

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	c := auth.FromContext(r.Context())
	// Use the token's original exp time so the revocation row can be GC'd.
	exp := c.IssuedAt.Add(s.signer.TTL())
	if err := s.db.Tokens.Add(r.Context(), c.JTI, c.UserID, exp); err != nil {
		writeError(w, http.StatusInternalServerError, "revoke failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- POST /api/v1/auth/change-password (F17) --------------------------------

type changePwReq struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	c := auth.FromContext(r.Context())
	var req changePwReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.CurrentPassword == "" || req.NewPassword == "" {
		writeError(w, http.StatusBadRequest, "current_password and new_password required")
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
	if req.NewPassword == req.CurrentPassword {
		writeError(w, http.StatusBadRequest, "new password must differ from current")
		return
	}

	u, err := s.db.Users.GetByID(r.Context(), c.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	if err := auth.CheckPassword(u.PasswordHash, req.CurrentPassword); err != nil {
		writeError(w, http.StatusUnauthorized, "current password incorrect")
		return
	}
	newHash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "hash failed")
		return
	}
	// SetPassword bumps password_changed_at, which invalidates the current
	// JWT too. We issue a fresh one so the caller's next request succeeds.
	if err := s.db.Users.SetPassword(r.Context(), c.UserID, newHash); err != nil {
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}
	tok, claims, err := s.signer.Issue(u.ID, u.Username, u.IsAdmin)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token issue failed")
		return
	}
	writeJSON(w, http.StatusOK, authResp{
		UserID:    u.ID,
		Username:  u.Username,
		Token:     tok,
		IsAdmin:   u.IsAdmin,
		ExpiresAt: claims.ExpiresAt.Unix(),
	})
}
