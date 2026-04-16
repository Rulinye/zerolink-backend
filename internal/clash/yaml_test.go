package clash

import (
	"strings"
	"testing"

	"github.com/rulinye/zerolink-backend/internal/storage"
)

func TestRender_Empty(t *testing.T) {
	out, err := Render("alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "proxies: []") {
		t.Fatalf("expected empty proxies block, got:\n%s", s)
	}
	if !strings.Contains(s, "MATCH,DIRECT") {
		t.Fatal("expected fallback DIRECT rule")
	}
}

func TestRender_VlessReality(t *testing.T) {
	nodes := []*storage.Node{{
		ID: 1, Name: "chuncheon-01", Region: "kr",
		Address: "gz.example.com", Port: 23456, Protocol: "vless+reality",
		ConfigJSON: `{
			"uuid": "d7880791-0513-4dd6-9136-d62a574f4b62",
			"flow": "xtls-rprx-vision",
			"servername": "www.microsoft.com",
			"public_key": "pok1AxeU6zh3yJZBg94MHqoFAF9dQrPATOtPrRiXGWA",
			"short_id": "7b076da999e6d37b",
			"fingerprint": "chrome",
			"udp": true
		}`,
		IsEnabled: true, SortOrder: 100,
	}}
	out, err := Render("alice", nodes)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)

	// Spot-check a handful of fields. We deliberately avoid asserting the
	// full YAML byte-for-byte because yaml.v3 may reorder map keys; the
	// important thing is each required field is present and the structure
	// parses as YAML.
	for _, want := range []string{
		"name: alice@chuncheon-01",
		"type: vless",
		"server: gz.example.com",
		"port: 23456",
		"uuid: d7880791-0513-4dd6-9136-d62a574f4b62",
		"public-key: pok1AxeU6zh3yJZBg94MHqoFAF9dQrPATOtPrRiXGWA",
		"short-id: 7b076da999e6d37b",
		"servername: www.microsoft.com",
		"flow: xtls-rprx-vision",
		"client-fingerprint: chrome",
		"name: PROXY",
		"name: AUTO",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in output:\n%s", want, s)
		}
	}
}

func TestRender_UnsupportedProtocolFails(t *testing.T) {
	nodes := []*storage.Node{{
		Name: "x", Protocol: "shadowsocks", ConfigJSON: `{}`,
	}}
	if _, err := Render("u", nodes); err == nil {
		t.Fatal("expected error for unsupported protocol")
	}
}

func TestRender_BadConfigJSONFails(t *testing.T) {
	nodes := []*storage.Node{{
		Name: "x", Protocol: "vless+reality", ConfigJSON: `not json`,
	}}
	if _, err := Render("u", nodes); err == nil {
		t.Fatal("expected error for malformed config_json")
	}
}
