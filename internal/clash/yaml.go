// Package clash renders the subscription YAML consumed by Clash Verge / Mihomo.
//
// Per phase-1-handover §8.6: Clash is picky about field names, indentation,
// and ordering. We use yaml.v3 with explicit struct tags rather than a
// text/template to guarantee well-formed output.
package clash

import (
	"encoding/json"
	"fmt"

	"github.com/rulinye/zerolink-backend/internal/storage"
	"gopkg.in/yaml.v3"
)

// Config is the top-level shape of a Clash config file. We emit only the
// fields the client actually needs; users can layer on local overrides.
type Config struct {
	Port               int              `yaml:"port"`
	SocksPort          int              `yaml:"socks-port"`
	AllowLan           bool             `yaml:"allow-lan"`
	Mode               string           `yaml:"mode"`
	LogLevel           string           `yaml:"log-level"`
	ExternalController string           `yaml:"external-controller,omitempty"`
	Proxies            []map[string]any `yaml:"proxies"`
	ProxyGroups        []ProxyGroup     `yaml:"proxy-groups"`
	Rules              []string         `yaml:"rules"`
}

// ProxyGroup is a Clash group entry (selector / url-test / fallback / ...).
type ProxyGroup struct {
	Name     string   `yaml:"name"`
	Type     string   `yaml:"type"`
	Proxies  []string `yaml:"proxies"`
	URL      string   `yaml:"url,omitempty"`
	Interval int      `yaml:"interval,omitempty"`
}

// nodeParams is the subset of fields we expect to find inside Node.ConfigJSON.
// Extra fields are tolerated and forwarded into the proxy map.
//
// For a vless+reality node the JSON looks like:
//
//	{
//	  "uuid": "d7880791-...",
//	  "flow": "xtls-rprx-vision",
//	  "servername": "www.microsoft.com",
//	  "public_key": "pok1AxeU6zh3yJZBg94MHqoFAF9dQrPATOtPrRiXGWA",
//	  "short_id": "7b076da999e6d37b",
//	  "fingerprint": "chrome",
//	  "udp": true,
//	  "skip_cert_verify": false
//	}
type nodeParams map[string]any

// Render serializes the given nodes into a Clash YAML config. The username
// is embedded into proxy names so multiple users can co-exist in one Clash
// instance during testing.
func Render(username string, nodes []*storage.Node) ([]byte, error) {
	if len(nodes) == 0 {
		// An empty Clash config still renders to valid YAML, but most
		// clients consider a zero-proxy subscription as broken. Emit
		// a single DIRECT proxy so the user sees something land.
		return renderEmpty(username), nil
	}

	proxies := make([]map[string]any, 0, len(nodes))
	names := make([]string, 0, len(nodes))

	for _, n := range nodes {
		p, err := nodeToClashProxy(username, n)
		if err != nil {
			return nil, fmt.Errorf("node %q: %w", n.Name, err)
		}
		proxies = append(proxies, p)
		names = append(names, p["name"].(string))
	}

	cfg := Config{
		Port:      7890,
		SocksPort: 7891,
		AllowLan:  false,
		Mode:      "rule",
		LogLevel:  "info",
		Proxies:   proxies,
		ProxyGroups: []ProxyGroup{
			{
				Name:    "PROXY",
				Type:    "select",
				Proxies: append([]string{"AUTO", "DIRECT"}, names...),
			},
			{
				Name:     "AUTO",
				Type:     "url-test",
				Proxies:  names,
				URL:      "https://www.gstatic.com/generate_204",
				Interval: 300,
			},
		},
		Rules: defaultRules(),
	}
	return yaml.Marshal(cfg)
}

// nodeToClashProxy translates a single storage.Node into a Clash proxy map.
// We only know how to render vless+reality in Phase 1 since that's the only
// protocol our infra serves; other protocols return an error.
func nodeToClashProxy(username string, n *storage.Node) (map[string]any, error) {
	var p nodeParams
	if err := json.Unmarshal([]byte(n.ConfigJSON), &p); err != nil {
		return nil, fmt.Errorf("config_json invalid: %w", err)
	}

	switch n.Protocol {
	case "vless+reality":
		return map[string]any{
			"name":       fmt.Sprintf("%s@%s", username, n.Name),
			"type":       "vless",
			"server":     n.Address,
			"port":       n.Port,
			"uuid":       p["uuid"],
			"network":    "tcp",
			"udp":        coalesceBool(p["udp"], true),
			"tls":        true,
			"flow":       coalesceString(p["flow"], "xtls-rprx-vision"),
			"servername": coalesceString(p["servername"], "www.microsoft.com"),
			"reality-opts": map[string]any{
				"public-key": p["public_key"],
				"short-id":   p["short_id"],
			},
			"client-fingerprint": coalesceString(p["fingerprint"], "chrome"),
			"skip-cert-verify":   coalesceBool(p["skip_cert_verify"], false),
		}, nil
	default:
		return nil, fmt.Errorf("protocol %q not supported in Phase 1", n.Protocol)
	}
}

func renderEmpty(_ string) []byte {
	const tpl = `port: 7890
socks-port: 7891
allow-lan: false
mode: rule
log-level: info
proxies: []
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - DIRECT
rules:
  - MATCH,DIRECT
`
	return []byte(tpl)
}

// defaultRules returns a small starter ruleset. End users layer their own on top.
func defaultRules() []string {
	return []string{
		"DOMAIN-SUFFIX,local,DIRECT",
		"IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
		"IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
		"IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
		"IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
		"GEOIP,CN,DIRECT",
		"MATCH,PROXY",
	}
}

func coalesceString(v any, def string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return def
}

func coalesceBool(v any, def bool) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	return def
}
