package server

import (
	"errors"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/rulinye/zerolink-backend/internal/auth"
	"github.com/rulinye/zerolink-backend/internal/storage"
)

// The admin UI uses the same JWT but stored in an HttpOnly cookie so a browser
// can navigate without manually attaching the Authorization header. This is a
// deliberately small surface: only admins log in via /admin/login.

const adminCookieName = "zl_admin"

func (s *Server) setAdminCookie(w http.ResponseWriter, token string, exp time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     adminCookieName,
		Value:    token,
		Path:     "/admin",
		Expires:  exp,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		// Note: Secure is intentionally left unset because Phase 1 backend
		// listens on 127.0.0.1 + SSH tunnel; once we put a TLS terminator
		// in front, set Secure: true in a follow-up.
	})
}

func (s *Server) clearAdminCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     adminCookieName,
		Value:    "",
		Path:     "/admin",
		MaxAge:   -1,
		HttpOnly: true,
	})
}

// cookieAuthMiddleware verifies the admin cookie. On failure it redirects to
// /admin/login rather than returning JSON; this is a browser-facing route.
func (s *Server) cookieAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ck, err := r.Cookie(adminCookieName)
		if err != nil || ck.Value == "" {
			http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
			return
		}
		claims, err := s.signer.Parse(ck.Value)
		if err != nil {
			s.clearAdminCookie(w)
			http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
			return
		}
		if !claims.IsAdmin {
			http.Error(w, "admin only", http.StatusForbidden)
			return
		}
		isRev, _ := s.db.Tokens.IsRevoked(r.Context(), claims.ID)
		if isRev {
			s.clearAdminCookie(w)
			http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- /admin/login (HTML) --------------------------------------------------

func (s *Server) handleUILogin(w http.ResponseWriter, r *http.Request) {
	s.renderTemplate(w, "login.html", map[string]any{
		"Error": r.URL.Query().Get("error"),
	})
}

func (s *Server) handleUILoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/login?error=bad+form", http.StatusSeeOther)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	u, err := s.db.Users.GetByUsername(r.Context(), username)
	if err != nil || !u.IsAdmin || u.IsDisabled {
		http.Redirect(w, r, "/admin/login?error=invalid+credentials", http.StatusSeeOther)
		return
	}
	if err := auth.CheckPassword(u.PasswordHash, password); err != nil {
		http.Redirect(w, r, "/admin/login?error=invalid+credentials", http.StatusSeeOther)
		return
	}
	tok, claims, err := s.signer.Issue(u.ID, u.Username, true)
	if err != nil {
		http.Redirect(w, r, "/admin/login?error=token+issue+failed", http.StatusSeeOther)
		return
	}
	_ = s.db.Users.TouchLastLogin(r.Context(), u.ID)
	s.setAdminCookie(w, tok, claims.ExpiresAt.Time)
	http.Redirect(w, r, "/admin/", http.StatusSeeOther)
}

func (s *Server) handleUILogout(w http.ResponseWriter, r *http.Request) {
	if ck, err := r.Cookie(adminCookieName); err == nil {
		if claims, err := s.signer.Parse(ck.Value); err == nil {
			_ = s.db.Tokens.Add(r.Context(), claims.ID, claims.UserID, claims.ExpiresAt.Time)
		}
	}
	s.clearAdminCookie(w)
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

// --- /admin/ dashboard ----------------------------------------------------

func (s *Server) handleUIDashboard(w http.ResponseWriter, r *http.Request) {
	uCount, _ := s.db.Users.Count(r.Context())
	invs, _ := s.db.Invites.List(r.Context(), true)
	nodes, _ := s.db.Nodes.List(r.Context(), false)
	s.renderTemplate(w, "dashboard.html", map[string]any{
		"UserCount":     uCount,
		"UnusedInvites": len(invs),
		"NodeCount":     len(nodes),
	})
}

// --- /admin/invites -------------------------------------------------------

func (s *Server) handleUIInvites(w http.ResponseWriter, r *http.Request) {
	invs, err := s.db.Invites.List(r.Context(), false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderTemplate(w, "invites.html", map[string]any{"Invites": invs, "Now": time.Now()})
}

func (s *Server) handleUICreateInvite(w http.ResponseWriter, r *http.Request) {
	// Resolve current admin from cookie to attribute the invite.
	ck, err := r.Cookie(adminCookieName)
	if err != nil {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}
	claims, err := s.signer.Parse(ck.Value)
	if err != nil {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}
	_ = r.ParseForm()
	note := strings.TrimSpace(r.FormValue("note"))

	code, err := newInviteCode()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	exp := time.Now().Add(7 * 24 * time.Hour)
	err = s.db.Invites.Insert(r.Context(), &storage.Invite{
		Code: code, CreatedBy: claims.UserID, ExpiresAt: exp, Note: note,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/invites", http.StatusSeeOther)
}

// --- /admin/users / /admin/nodes ------------------------------------------

func (s *Server) handleUIUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.db.Users.List(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderTemplate(w, "users.html", map[string]any{"Users": users})
}

func (s *Server) handleUINodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.db.Nodes.List(r.Context(), false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderTemplate(w, "nodes.html", map[string]any{"Nodes": nodes})
}

// renderTemplate executes a named template with a "Title" derived from the name.
func (s *Server) renderTemplate(w http.ResponseWriter, name string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	if _, ok := data["Title"]; !ok {
		data["Title"] = strings.TrimSuffix(name, ".html")
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tpl.ExecuteTemplate(w, name, data); err != nil {
		s.log.Error("template render failed", "name", name, "err", err)
	}
}

// LoadTemplates parses every *.html under templatesFS into a single template
// set. The "layout.html" file MUST define a top-level template named "layout"
// that yields to a per-page block.
func LoadTemplates(templatesFS interface {
	ReadFile(name string) ([]byte, error)
}) (*template.Template, error) {
	return nil, errors.New("LoadTemplates: deprecated, use LoadTemplatesFS")
}
