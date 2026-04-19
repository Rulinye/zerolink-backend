package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/rulinye/zerolink-backend/internal/auth"
	"github.com/rulinye/zerolink-backend/internal/clash"
	"github.com/rulinye/zerolink-backend/internal/storage"
)

// --- GET /api/v1/nodes ----------------------------------------------------

type nodeView struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Region   string `json:"region"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.db.Nodes.List(r.Context(), true)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list nodes failed")
		return
	}
	out := make([]nodeView, len(nodes))
	for i, n := range nodes {
		out[i] = nodeView{
			ID: n.ID, Name: n.Name, Region: n.Region,
			Address: n.Address, Port: n.Port, Protocol: n.Protocol,
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": out})
}

// --- GET /api/v1/nodes/{id}/config ----------------------------------------

func (s *Server) handleNodeConfig(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	n, err := s.db.Nodes.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "node not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "node lookup failed")
		return
	}
	if !n.IsEnabled {
		writeError(w, http.StatusNotFound, "node not enabled")
		return
	}

	// Parse the opaque ConfigJSON so the client gets structured fields.
	var cfg map[string]any
	if err := json.Unmarshal([]byte(n.ConfigJSON), &cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "config_json malformed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":       n.ID,
		"name":     n.Name,
		"region":   n.Region,
		"address":  n.Address,
		"port":     n.Port,
		"protocol": n.Protocol,
		"params":   cfg,
	})
}

// --- POST /api/v1/subscriptions -------------------------------------------

type createSubReq struct {
	Name string `json:"name"`
}

type subView struct {
	Token         string  `json:"token"`
	URL           string  `json:"url"`
	Name          string  `json:"name"`
	CreatedAt     string  `json:"created_at"`
	LastFetchedAt *string `json:"last_fetched_at,omitempty"`
	FetchCount    int64   `json:"fetch_count"`
	Revoked       bool    `json:"revoked"`
}

func (s *Server) handleCreateSubscription(w http.ResponseWriter, r *http.Request) {
	c := auth.FromContext(r.Context())
	var req createSubReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		req.Name = "default"
	}
	if len(req.Name) > 64 {
		writeError(w, http.StatusBadRequest, "name too long")
		return
	}

	sub, err := s.db.Subscriptions.Create(r.Context(), c.UserID, req.Name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "insert subscription failed")
		return
	}
	writeJSON(w, http.StatusOK, viewOf(r, sub))
}

func (s *Server) handleListSubscriptions(w http.ResponseWriter, r *http.Request) {
	c := auth.FromContext(r.Context())
	subs, err := s.db.Subscriptions.ListByUser(r.Context(), c.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		return
	}
	out := make([]subView, len(subs))
	for i, s := range subs {
		out[i] = viewOf(r, s)
	}
	writeJSON(w, http.StatusOK, map[string]any{"subscriptions": out})
}

func (s *Server) handleRevokeSubscription(w http.ResponseWriter, r *http.Request) {
	c := auth.FromContext(r.Context())
	tok := chi.URLParam(r, "token")
	if err := s.db.Subscriptions.Revoke(r.Context(), tok, c.UserID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "subscription not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "revoke failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- GET /sub/{token}  (no auth — token IS the credential) ----------------

func (s *Server) handleSubscriptionFetch(w http.ResponseWriter, r *http.Request) {
	tok := chi.URLParam(r, "token")
	sub, err := s.db.Subscriptions.GetByToken(r.Context(), tok)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "lookup failed", http.StatusInternalServerError)
		return
	}
	if sub.Revoked {
		http.Error(w, "subscription revoked", http.StatusGone)
		return
	}
	u, err := s.db.Users.GetByID(r.Context(), sub.UserID)
	if err != nil {
		http.Error(w, "user lookup failed", http.StatusInternalServerError)
		return
	}
	if u.IsDisabled {
		http.Error(w, "account disabled", http.StatusForbidden)
		return
	}
	nodes, err := s.db.Nodes.List(r.Context(), true)
	if err != nil {
		http.Error(w, "nodes lookup failed", http.StatusInternalServerError)
		return
	}
	body, err := clash.Render(u.Username, nodes)
	if err != nil {
		http.Error(w, "render failed", http.StatusInternalServerError)
		return
	}

	// Best-effort: bump fetch counters in background so the response isn't
	// blocked by a stray write contention. Use context.Background() because
	// r.Context() is canceled the moment the response is flushed.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.db.Subscriptions.TouchFetch(ctx, tok)
	}()

	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.Header().Set("Subscription-Userinfo",
		"upload=0; download=0; total=0; expire=0")
	w.Header().Set("Profile-Update-Interval", "24")
	w.Header().Set("Content-Disposition",
		`attachment; filename="zerolink-`+u.Username+`.yaml"`)
	_, _ = w.Write(body)
}

// --- helpers --------------------------------------------------------------

func newOpaqueToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func viewOf(r *http.Request, s *storage.Subscription) subView {
	scheme := "https"
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
		scheme = "http"
	}
	host := r.Host
	if h := r.Header.Get("X-Forwarded-Host"); h != "" {
		host = h
	}
	v := subView{
		Token:      s.Token,
		URL:        scheme + "://" + host + "/sub/" + s.Token,
		Name:       s.Name,
		CreatedAt:  s.CreatedAt.Format(time.RFC3339),
		FetchCount: s.FetchCount,
		Revoked:    s.Revoked,
	}
	if s.LastFetchedAt != nil {
		t := s.LastFetchedAt.Format(time.RFC3339)
		v.LastFetchedAt = &t
	}
	return v
}
