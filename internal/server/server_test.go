package server

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rulinye/zerolink-backend/internal/auth"
	"github.com/rulinye/zerolink-backend/internal/config"
	"github.com/rulinye/zerolink-backend/internal/storage"
)

// newTestServer wires up a real DB on disk (per phase-1-handover §4: real
// SQLite, not mocks) plus an httptest server. Returns the URL and a cleanup.
func newTestServer(t *testing.T) (string, *Server, func()) {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte("a"), 32)
	signer, err := auth.NewSigner(secret, time.Hour, "test")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Listen: "127.0.0.1:0", DBPath: filepath.Join(dir, "test.db"),
		JWTSecret: secret, JWTTTL: time.Hour, JWTIssuer: "test",
		AdminUIEnabled: false, // we only test the JSON API here
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := New(cfg, db, signer, logger, nil, nil)

	// httptest provides the listener.
	httpSrv := httptest.NewServer(s.Handler())
	cleanup := func() {
		httpSrv.Close()
		db.Close()
		_ = os.RemoveAll(dir)
	}
	return httpSrv.URL, s, cleanup
}

// seedAdmin inserts an admin user "admin"/"adminpw" and returns its id.
func seedAdmin(t *testing.T, s *Server) int64 {
	t.Helper()
	hash, err := auth.HashPassword("adminpw1")
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.db.Users.Insert(t.Context(), &storage.User{
		Username: "admin", PasswordHash: hash, IsAdmin: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func doJSON(t *testing.T, method, url string, body any, token string) (*http.Response, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, url, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, b
}

func TestPing(t *testing.T) {
	url, _, cleanup := newTestServer(t)
	defer cleanup()
	resp, body := doJSON(t, "GET", url+"/ping", nil, "")
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), `"ok":true`) {
		t.Fatalf("unexpected body: %s", body)
	}
}

// TestFullFlow exercises: admin login → create invite → user register with
// invite → user login → /me → /nodes (empty) → create subscription →
// fetch /sub/{token}.
func TestFullFlow(t *testing.T) {
	url, s, cleanup := newTestServer(t)
	defer cleanup()
	seedAdmin(t, s)

	// 1) Admin logs in.
	resp, body := doJSON(t, "POST", url+"/api/v1/auth/login",
		map[string]string{"username": "admin", "password": "adminpw1"}, "")
	if resp.StatusCode != 200 {
		t.Fatalf("admin login status=%d body=%s", resp.StatusCode, body)
	}
	var login loginResp
	if err := json.Unmarshal(body, &login); err != nil {
		t.Fatal(err)
	}
	if !login.IsAdmin || login.Token == "" {
		t.Fatalf("unexpected login resp: %+v", login)
	}
	adminTok := login.Token

	// 2) Admin creates an invite.
	resp, body = doJSON(t, "POST", url+"/api/v1/admin/invites",
		map[string]any{"note": "for-alice", "ttl_hours": 24, "count": 1}, adminTok)
	if resp.StatusCode != 201 {
		t.Fatalf("create invite status=%d body=%s", resp.StatusCode, body)
	}
	var inviteResp struct {
		Invites []struct{ Code string } `json:"invites"`
	}
	if err := json.Unmarshal(body, &inviteResp); err != nil {
		t.Fatal(err)
	}
	if len(inviteResp.Invites) != 1 || inviteResp.Invites[0].Code == "" {
		t.Fatalf("expected 1 invite code, got %+v", inviteResp)
	}
	code := inviteResp.Invites[0].Code

	// 3) User registers with invite.
	resp, body = doJSON(t, "POST", url+"/api/v1/auth/register",
		map[string]string{"invite_code": code, "username": "alice", "password": "alicepw1"}, "")
	if resp.StatusCode != 200 {
		t.Fatalf("register status=%d body=%s", resp.StatusCode, body)
	}
	var reg registerResp
	if err := json.Unmarshal(body, &reg); err != nil {
		t.Fatal(err)
	}
	if reg.Username != "alice" || reg.Token == "" {
		t.Fatalf("unexpected register resp: %+v", reg)
	}
	aliceTok := reg.Token

	// 4) Re-using same invite must fail.
	resp, body = doJSON(t, "POST", url+"/api/v1/auth/register",
		map[string]string{"invite_code": code, "username": "bob", "password": "bobpw123"}, "")
	if resp.StatusCode != 400 {
		t.Fatalf("reuse should 400, got %d body=%s", resp.StatusCode, body)
	}

	// 5) /me works.
	resp, body = doJSON(t, "GET", url+"/api/v1/auth/me", nil, aliceTok)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"username":"alice"`) {
		t.Fatalf("/me failed: status=%d body=%s", resp.StatusCode, body)
	}

	// 6) Seed a node directly via repo so /nodes returns something.
	if err := s.db.Nodes.Upsert(t.Context(), &storage.Node{
		Name: "chuncheon-01", Region: "kr", Address: "gz.example.com",
		Port: 23456, Protocol: "vless+reality",
		ConfigJSON: `{"uuid":"d7880791-0513-4dd6-9136-d62a574f4b62","flow":"xtls-rprx-vision","servername":"www.microsoft.com","public_key":"pok1AxeU6zh3yJZBg94MHqoFAF9dQrPATOtPrRiXGWA","short_id":"7b076da999e6d37b","fingerprint":"chrome"}`,
		IsEnabled:  true, SortOrder: 100,
	}); err != nil {
		t.Fatal(err)
	}

	// 7) /nodes returns the seeded node.
	resp, body = doJSON(t, "GET", url+"/api/v1/nodes", nil, aliceTok)
	if resp.StatusCode != 200 || !strings.Contains(string(body), "chuncheon-01") {
		t.Fatalf("/nodes failed: status=%d body=%s", resp.StatusCode, body)
	}

	// 8) Alice creates a subscription.
	resp, body = doJSON(t, "POST", url+"/api/v1/subscriptions",
		map[string]string{"name": "macbook"}, aliceTok)
	if resp.StatusCode != 201 {
		t.Fatalf("create sub failed: status=%d body=%s", resp.StatusCode, body)
	}
	var sv subView
	if err := json.Unmarshal(body, &sv); err != nil {
		t.Fatal(err)
	}
	if sv.Token == "" || !strings.Contains(sv.URL, "/sub/") {
		t.Fatalf("unexpected sub view: %+v", sv)
	}

	// 9) Fetch /sub/{token} without any auth header — must return YAML.
	resp, body = doJSON(t, "GET", url+"/sub/"+sv.Token, nil, "")
	if resp.StatusCode != 200 {
		t.Fatalf("/sub fetch failed: status=%d body=%s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/yaml") {
		t.Fatalf("want yaml content-type, got %q", ct)
	}
	if !strings.Contains(string(body), "alice@chuncheon-01") {
		t.Fatalf("yaml missing expected proxy name:\n%s", body)
	}

	// 10) Logout: revoking the token should make /me 401 next time.
	resp, body = doJSON(t, "POST", url+"/api/v1/auth/logout", nil, aliceTok)
	if resp.StatusCode != 200 {
		t.Fatalf("logout failed: %d %s", resp.StatusCode, body)
	}
	resp, _ = doJSON(t, "GET", url+"/api/v1/auth/me", nil, aliceTok)
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401 after logout, got %d", resp.StatusCode)
	}
}

func TestNonAdmin_CannotAccessAdminEndpoints(t *testing.T) {
	url, s, cleanup := newTestServer(t)
	defer cleanup()

	// Make a non-admin user directly.
	hash, _ := auth.HashPassword("plebpw12")
	_, err := s.db.Users.Insert(t.Context(), &storage.User{
		Username: "pleb", PasswordHash: hash, IsAdmin: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, body := doJSON(t, "POST", url+"/api/v1/auth/login",
		map[string]string{"username": "pleb", "password": "plebpw12"}, "")
	if resp.StatusCode != 200 {
		t.Fatalf("login failed: %d %s", resp.StatusCode, body)
	}
	var l loginResp
	_ = json.Unmarshal(body, &l)

	resp, _ = doJSON(t, "GET", url+"/api/v1/admin/users", nil, l.Token)
	if resp.StatusCode != 403 {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestRegister_BadInput(t *testing.T) {
	url, _, cleanup := newTestServer(t)
	defer cleanup()
	cases := []map[string]string{
		{"invite_code": "X", "username": "ab", "password": "longenough"},    // username too short
		{"invite_code": "X", "username": "alice", "password": "short"},      // password too short
		{"invite_code": "X", "username": "Alice", "password": "longenough"}, // uppercase
	}
	for i, c := range cases {
		resp, body := doJSON(t, "POST", url+"/api/v1/auth/register", c, "")
		if resp.StatusCode != 400 {
			t.Errorf("case %d: want 400, got %d body=%s", i, resp.StatusCode, body)
		}
	}
}
