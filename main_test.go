package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// newTestServer wires the same routes main() uses, without the slog
// initialization or signal handling. Keeps tests fast and silent.
func newTestServer() http.Handler {
	r := chi.NewRouter()
	r.Get("/ping", handlePing)
	r.Get("/version", handleVersion)
	return r
}

func TestPing(t *testing.T) {
	srv := httptest.NewServer(newTestServer())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/ping")
	if err != nil {
		t.Fatalf("GET /ping: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}

	body, _ := io.ReadAll(resp.Body)
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("invalid json: %v (body=%s)", err, body)
	}
	if got["ok"] != true {
		t.Errorf(`got["ok"] = %v, want true`, got["ok"])
	}
	if got["service"] != "zerolink-backend" {
		t.Errorf(`got["service"] = %v, want "zerolink-backend"`, got["service"])
	}
	if _, ok := got["time"].(string); !ok {
		t.Errorf(`got["time"] = %v, want string`, got["time"])
	}
}

func TestVersion(t *testing.T) {
	srv := httptest.NewServer(newTestServer())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/version")
	if err != nil {
		t.Fatalf("GET /version: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("invalid json: %v (body=%s)", err, body)
	}
	if _, ok := got["version"].(string); !ok {
		t.Errorf(`got["version"] = %v, want string`, got["version"])
	}
}
