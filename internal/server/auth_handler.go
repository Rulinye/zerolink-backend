package server

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/rulinye/zerolink-backend/internal/auth"
	"github.com/rulinye/zerolink-backend/internal/storage"
)

// --- /ping and /version (Phase 0 carryover) -------------------------------

func (s *Server) handlePing(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"service": "zerolink-backend",
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"version": s.Version})
}

// --- POST /api/v1/auth/register -------------------------------------------

type registerReq struct {
	InviteCode string `json:"invite_code"`
	Username   string `json:"username"`
	Password   string `json:"password"`
}

type registerResp struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	Token    string `json:"token"`
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	req.InviteCode = strings.TrimSpace(strings.ToUpper(req.InviteCode))

	if !validUsername(req.Username) {
		writeError(w, http.StatusBadRequest, "username must be 3-32 chars, [a-z0-9_-]")
		return
	}
	if len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "password must be >=8 chars")
		return
	}

	// Verify invite is valid (but don't consume yet — race with user insert).
	in, err := s.db.Invites.Get(r.Context(), req.InviteCode)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusBadRequest, "invite code not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "invite lookup failed")
		return
	}
	if in.IsConsumed() {
		writeError(w, http.StatusBadRequest, "invite code already used")
		return
	}
	if in.IsExpired() {
		writeError(w, http.StatusBadRequest, "invite code expired")
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	uid, err := s.db.Users.Insert(r.Context(), &storage.User{
		Username:     req.Username,
		PasswordHash: hash,
		IsAdmin:      false,
	})
	if err != nil {
		if errors.Is(err, storage.ErrUsernameTaken) {
			writeError(w, http.StatusConflict, "username already taken")
			return
		}
		s.log.Error("user insert failed", "err", err)
		writeError(w, http.StatusInternalServerError, "could not create user")
		return
	}

	// Now consume the invite. If this fails (e.g. raced and lost), we leave the
	// user created — better than rolling back and risking inconsistency.
	if err := s.db.Invites.Consume(r.Context(), req.InviteCode, uid); err != nil {
		s.log.Warn("invite consume after user insert failed",
			"err", err, "code", req.InviteCode, "uid", uid)
		// Continue: user exists, code may be stuck visible-but-unusable.
	}

	tok, _, err := s.signer.Issue(uid, req.Username, false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token issue failed")
		return
	}
	writeJSON(w, http.StatusOK, registerResp{UserID: uid, Username: req.Username, Token: tok})
}

// --- POST /api/v1/auth/login ----------------------------------------------

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResp struct {
	UserID    int64  `json:"user_id"`
	Username  string `json:"username"`
	IsAdmin   bool   `json:"is_admin"`
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Username = strings.TrimSpace(req.Username)

	u, err := s.db.Users.GetByUsername(r.Context(), req.Username)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			// Same response shape as wrong password: no user enumeration.
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		writeError(w, http.StatusInternalServerError, "user lookup failed")
		return
	}
	if u.IsDisabled {
		writeError(w, http.StatusForbidden, "account disabled")
		return
	}
	if err := auth.CheckPassword(u.PasswordHash, req.Password); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	tok, claims, err := s.signer.Issue(u.ID, u.Username, u.IsAdmin)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token issue failed")
		return
	}
	_ = s.db.Users.TouchLastLogin(r.Context(), u.ID)

	writeJSON(w, http.StatusOK, loginResp{
		UserID:    u.ID,
		Username:  u.Username,
		IsAdmin:   u.IsAdmin,
		Token:     tok,
		ExpiresAt: claims.ExpiresAt.Unix(),
	})
}

// --- GET /api/v1/auth/me --------------------------------------------------

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	c := auth.FromContext(r.Context())
	u, err := s.db.Users.GetByID(r.Context(), c.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "user lookup failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":    u.ID,
		"username":   u.Username,
		"is_admin":   u.IsAdmin,
		"created_at": u.CreatedAt.Format(time.RFC3339),
	})
}

// --- POST /api/v1/auth/logout ---------------------------------------------

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	c := auth.FromContext(r.Context())
	if err := s.db.Tokens.Add(r.Context(), c.ID, c.UserID, c.ExpiresAt.Time); err != nil {
		s.log.Warn("revoke add failed", "err", err)
		writeError(w, http.StatusInternalServerError, "logout failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// --- helpers --------------------------------------------------------------

func validUsername(u string) bool {
	if len(u) < 3 || len(u) > 32 {
		return false
	}
	for _, r := range u {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '-':
		default:
			return false
		}
	}
	return true
}
