//! Runtime configuration loaded from environment variables.
//!
//! Mirrors the env-driven config style of zerolink-backend (Go side):
//! every knob is a `ZL_BROKER_*` env var, missing required vars cause
//! Load() to return an error so systemd flags the start-up failure
//! rather than the broker booting with bad defaults.
//!
//! Required vars (no default):
//!   ZL_BROKER_SERVICE_TOKEN          — Bearer token issued by backend's
//!                                      gen-service-token CLI.
//!   ZL_BROKER_BACKEND_FINGERPRINT    — sha256 hex of the backend's leaf
//!                                      cert (lowercase, no separators).
//!   ZL_BROKER_SHORT_ID               — 2-3 char globally-unique label
//!                                      (e.g. "KR", "GZ"). Used as the
//!                                      prefix in room codes ("KR-XK7P9R").
//!
//! Optional vars (defaults shown):
//!   ZL_BROKER_LISTEN_HTTP=0.0.0.0:7842        — signaling HTTP listener
//!   ZL_BROKER_LISTEN_QUIC=0.0.0.0:7843        — datapath QUIC listener (2d)
//!   ZL_BROKER_DB_PATH=/var/lib/zerolink-broker/broker.db
//!   ZL_BROKER_BACKEND_URL=https://168.107.55.126:8443
//!   ZL_BROKER_VERIFY_CACHE_TTL=300            — JWT verify cache TTL, seconds
//!   ZL_BROKER_REQUEST_TIMEOUT=10              — backend HTTP timeout, seconds
//!   ZL_BROKER_LOG_JSON=true                   — slog-style JSON logs

use anyhow::{anyhow, Context, Result};
use std::env;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    pub listen_http: String,
    pub listen_quic: String,

    /// Externally reachable host:port the broker exposes to clients
    /// for QUIC datapath connections. In dev defaults to listen_quic;
    /// in prod set this to the broker's public IP/hostname:port that
    /// is reachable from outside (when listen_quic binds to 0.0.0.0).
    pub datapath_external_host: String,

    pub db_path: String,
    pub backend_url: String,
    pub backend_fingerprint: String,
    pub service_token: String,
    pub short_id: String,
    pub verify_cache_ttl: Duration,
    pub request_timeout: Duration,
    pub log_json: bool,
}

impl Config {
    /// Load configuration from env. Returns Err with a clear message on
    /// missing required vars or invalid formats.
    pub fn load() -> Result<Self> {
        let listen_http = env_or("ZL_BROKER_LISTEN_HTTP", "0.0.0.0:7842");
        let listen_quic = env_or("ZL_BROKER_LISTEN_QUIC", "0.0.0.0:7843");
        let datapath_external_host = env_or("ZL_BROKER_DATAPATH_EXTERNAL_HOST", &listen_quic);
        if datapath_external_host.trim().is_empty() {
            return Err(anyhow!("ZL_BROKER_DATAPATH_EXTERNAL_HOST is empty"));
        }
        let db_path = env_or("ZL_BROKER_DB_PATH", "/var/lib/zerolink-broker/broker.db");
        let backend_url = env_or("ZL_BROKER_BACKEND_URL", "https://168.107.55.126:8443");

        let backend_fingerprint = env::var("ZL_BROKER_BACKEND_FINGERPRINT").context(
            "ZL_BROKER_BACKEND_FINGERPRINT is required (sha256 hex of backend's leaf cert)",
        )?;
        validate_fingerprint(&backend_fingerprint)?;

        let service_token = env::var("ZL_BROKER_SERVICE_TOKEN").context(
            "ZL_BROKER_SERVICE_TOKEN is required (provisioned via backend gen-service-token CLI)",
        )?;
        if service_token.is_empty() {
            return Err(anyhow!("ZL_BROKER_SERVICE_TOKEN is empty"));
        }

        let short_id = env::var("ZL_BROKER_SHORT_ID")
            .context("ZL_BROKER_SHORT_ID is required (2-3 char broker label, e.g. 'KR')")?;
        validate_short_id(&short_id)?;

        let verify_cache_ttl = parse_secs("ZL_BROKER_VERIFY_CACHE_TTL", 300)?;
        let request_timeout = parse_secs("ZL_BROKER_REQUEST_TIMEOUT", 10)?;

        let log_json = env_bool("ZL_BROKER_LOG_JSON", true);

        Ok(Config {
            listen_http,
            listen_quic,
            datapath_external_host,
            db_path,
            backend_url,
            backend_fingerprint,
            service_token,
            short_id,
            verify_cache_ttl,
            request_timeout,
            log_json,
        })
    }
}

fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_bool(key: &str, default: bool) -> bool {
    match env::var(key) {
        Ok(v) => match v.to_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            _ => default,
        },
        Err(_) => default,
    }
}

fn parse_secs(key: &str, default_secs: u64) -> Result<Duration> {
    let raw = env::var(key).unwrap_or_else(|_| default_secs.to_string());
    // Accept "300" or "300s". Anything else fails.
    let trimmed = raw.trim_end_matches('s');
    let n: u64 = trimmed.parse().with_context(|| {
        format!("{key}: invalid duration {raw:?} (expected integer seconds, e.g. 300 or 300s)")
    })?;
    Ok(Duration::from_secs(n))
}

fn validate_fingerprint(fp: &str) -> Result<()> {
    // sha256 = 32 bytes = 64 hex chars
    if fp.len() != 64 {
        return Err(anyhow!(
            "ZL_BROKER_BACKEND_FINGERPRINT has length {}, expected 64 (sha256 hex)",
            fp.len()
        ));
    }
    if !fp
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(anyhow!(
            "ZL_BROKER_BACKEND_FINGERPRINT must be lowercase hex (no colons, no uppercase)"
        ));
    }
    Ok(())
}

fn validate_short_id(s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 8 {
        return Err(anyhow!(
            "ZL_BROKER_SHORT_ID must be 1..8 chars; got len {}",
            s.len()
        ));
    }
    if !s.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(anyhow!(
            "ZL_BROKER_SHORT_ID must be alphanumeric ASCII; got {s:?}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_validation() {
        assert!(validate_fingerprint(
            "34a160d3784fdec281d0e2126151bac4dec33f750e1026f44027521785e85163"
        )
        .is_ok());
        // wrong length
        assert!(validate_fingerprint("abcd").is_err());
        // uppercase rejected (broker normalizes to lowercase elsewhere)
        assert!(validate_fingerprint(
            "34A160D3784FDEC281D0E2126151BAC4DEC33F750E1026F44027521785E85163"
        )
        .is_err());
        // colons rejected
        assert!(validate_fingerprint(
            "34:a1:60:d3:78:4f:de:c2:81:d0:e2:12:61:51:ba:c4:de:c3:3f:75:0e:10:26:f4:40:27:52:17:85:e8:51:63"
        )
        .is_err());
    }

    #[test]
    fn short_id_validation() {
        assert!(validate_short_id("KR").is_ok());
        assert!(validate_short_id("GZ").is_ok());
        assert!(validate_short_id("KR1").is_ok());
        assert!(validate_short_id("").is_err());
        assert!(validate_short_id("KR-1").is_err()); // hyphen rejected; reserved for room code separator
        assert!(validate_short_id("TOOLONGFOO").is_err());
    }
}
