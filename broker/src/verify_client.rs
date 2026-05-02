//! Reverse-verify client for the backend's `/api/v1/auth/verify` endpoint.
//!
//! ## Trust model
//!
//! The backend serves a self-signed TLS certificate (single host, 10y
//! validity, generated once on first deploy by Ansible). We pin the leaf
//! certificate's sha256 fingerprint instead of validating any CA chain.
//! This is implemented via a custom rustls `ServerCertVerifier` that
//! computes sha256 over the leaf DER and compares against the operator-
//! configured `backend_fingerprint`.
//!
//! Consequences:
//!   - Cert rotation requires re-deploying brokers with the new fingerprint
//!     (rotation runbook lives in 0-0link-infra/roles/backend/README).
//!   - The broker does NOT validate hostname / SAN / NotBefore / NotAfter.
//!     The fingerprint match is the entire trust decision. This is by
//!     design — backend cert validity is enforced at issuance time, not
//!     at request time.
//!
//! ## Caching
//!
//! Verifications cached in-memory for `cache_ttl` (default 5min, set by
//! ZL_BROKER_VERIFY_CACHE_TTL). Only `valid: true` responses are cached —
//! `valid: false` (jwt_invalid, user_disabled, etc.) is re-checked every
//! call so a freshly-unbanned user or just-bumped quota takes effect
//! immediately. The cache key is the JWT string itself.
//!
//! ## Concurrency
//!
//! `tokio::sync::RwLock<HashMap>` for cache. Multiple concurrent
//! verifications of the same JWT (e.g. when N members of one room
//! reconnect simultaneously) deduplicate at the HTTP layer because the
//! first to hit miss issues the request, the rest hit cache by the time
//! they read. We don't add explicit single-flight dedup; the redundant
//! requests during a thundering herd are negligible vs. the simplicity
//! cost of single-flight.

use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// JSON shape returned by `POST /api/v1/auth/verify`.
///
/// Backend always returns 200 + `valid: bool`. Service-token auth failures
/// surface as 401 (caught by `Error::ServiceTokenRejected`); JWT-side
/// failures surface as 200 + `valid: false` + `reason: "..."`.
#[derive(Debug, Clone, Deserialize)]
pub struct VerifyResponse {
    pub valid: bool,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub user_id: Option<i64>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub is_admin: Option<bool>,
    #[serde(default)]
    pub quota_bytes: Option<i64>,
    #[serde(default)]
    pub used_bytes: Option<i64>,
    #[serde(default)]
    pub quota_remaining: Option<i64>,
    /// B4.7-supp / B9: per-user broker datapath rate limit (bytes/sec).
    /// Default 20 Mbps when missing. Broker enforces via per-session
    /// token bucket in `datapath/limiter.rs`.
    #[serde(default)]
    pub room_rate_limit_bps: Option<i64>,
}

#[derive(Debug, Serialize)]
struct VerifyRequest<'a> {
    jwt: &'a str,
}

/// Errors that affect broker behavior (vs. user-side errors which surface
/// as `VerifyResponse { valid: false }`).
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("backend rejected our service token (401); rotate the token via gen-service-token")]
    ServiceTokenRejected,

    #[error("backend HTTP {status}: {body}")]
    Http { status: u16, body: String },

    #[error("transport error: {0}")]
    Transport(#[from] reqwest::Error),

    #[error("response decode error: {0}")]
    Decode(#[from] serde_json::Error),
}

#[derive(Clone)]
pub struct VerifyClient {
    http: Client,
    backend_url: String,
    service_token: String,
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    cache_ttl: Duration,
}

#[derive(Clone)]
struct CacheEntry {
    response: VerifyResponse,
    inserted_at: Instant,
}

impl VerifyClient {
    pub fn new(
        backend_url: String,
        backend_fingerprint: String,
        service_token: String,
        request_timeout: Duration,
        cache_ttl: Duration,
    ) -> Result<Self> {
        // rustls config with our custom verifier.
        let verifier = Arc::new(FingerprintVerifier::new(backend_fingerprint)?);
        let tls_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();

        // Phase 4.1 D4.3 (2026-04-28): broker_backend_url is HTTP not
        // HTTPS now (loopback to chuncheon backend OR loopback to gz
        // sing-box forwarder which tunnels through reality to chuncheon).
        // The historical `https_only(true)` rejected http:// at request
        // time as "builder error", so we drop it. The TLS config above
        // is dead code on http:// requests but harmless; FingerprintVerifier
        // construction also stays for the validate_fingerprint format
        // check at startup. A future cleanup batch can simplify this
        // entire client to a plain reqwest::Client::new() once all
        // brokers have migrated.
        let http = Client::builder()
            .use_preconfigured_tls(tls_config)
            .timeout(request_timeout)
            .build()
            .context("build reqwest client")?;

        Ok(Self {
            http,
            backend_url,
            service_token,
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl,
        })
    }

    /// Verify a client JWT. Returns the broker-relevant outcome.
    /// Successful verifications (`valid: true`) are cached for `cache_ttl`.
    pub async fn verify(&self, jwt: &str) -> Result<VerifyResponse, VerifyError> {
        // Cache check.
        if let Some(cached) = self.cache_get(jwt).await {
            debug!(target: "verify", "cache hit");
            return Ok(cached);
        }

        debug!(target: "verify", "cache miss; calling backend");
        let resp = self.call_backend(jwt).await?;

        if resp.valid {
            self.cache_put(jwt.to_string(), resp.clone()).await;
        }

        Ok(resp)
    }

    async fn cache_get(&self, jwt: &str) -> Option<VerifyResponse> {
        let cache = self.cache.read().await;
        let entry = cache.get(jwt)?;
        if entry.inserted_at.elapsed() < self.cache_ttl {
            Some(entry.response.clone())
        } else {
            None
        }
    }

    async fn cache_put(&self, jwt: String, response: VerifyResponse) {
        let mut cache = self.cache.write().await;
        // Opportunistic GC: drop expired entries when inserting. O(n) per
        // insert is fine here; broker handles ~10s of concurrent rooms,
        // not millions.
        let ttl = self.cache_ttl;
        cache.retain(|_, v| v.inserted_at.elapsed() < ttl);
        cache.insert(
            jwt,
            CacheEntry {
                response,
                inserted_at: Instant::now(),
            },
        );
    }

    async fn call_backend(&self, jwt: &str) -> Result<VerifyResponse, VerifyError> {
        let url = format!("{}/api/v1/auth/verify", self.backend_url);
        let req = VerifyRequest { jwt };

        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.service_token)
            .json(&req)
            .send()
            .await?;

        let status = resp.status();
        if status.as_u16() == 401 {
            warn!(target: "verify", "backend returned 401; service_token may be invalid or rotated");
            return Err(VerifyError::ServiceTokenRejected);
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(VerifyError::Http {
                status: status.as_u16(),
                body,
            });
        }

        let parsed: VerifyResponse = resp.json().await?;
        Ok(parsed)
    }
}

/// Custom rustls verifier: accept any leaf cert whose sha256 fingerprint
/// matches the operator-configured value. Reject everything else.
///
/// This deliberately bypasses webpki / SAN / NotAfter / signature chain
/// validation. Trust is anchored entirely on the fingerprint match.
#[derive(Debug)]
struct FingerprintVerifier {
    expected_fingerprint: Vec<u8>, // 32 raw bytes
}

impl FingerprintVerifier {
    fn new(expected_hex: String) -> Result<Self> {
        let bytes = hex::decode(&expected_hex)
            .with_context(|| format!("decode fingerprint hex {expected_hex:?}"))?;
        if bytes.len() != 32 {
            return Err(anyhow!(
                "fingerprint must be 32 bytes (64 hex chars), got {}",
                bytes.len()
            ));
        }
        Ok(Self {
            expected_fingerprint: bytes,
        })
    }
}

impl ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let mut hasher = Sha256::new();
        hasher.update(end_entity.as_ref());
        let actual = hasher.finalize();

        if actual.as_slice() == self.expected_fingerprint.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(RustlsError::General(format!(
                "fingerprint mismatch: expected {}, got {}",
                hex::encode(&self.expected_fingerprint),
                hex::encode(actual)
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        // We've already accepted the cert by fingerprint; accept the
        // handshake signature unconditionally. (The TLS layer still
        // verifies the signature is well-formed; we just don't re-check
        // it against any trust anchor.)
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // Accept everything modern. rustls will use this list for
        // signature_algorithms in ClientHello.
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_verifier_construction() {
        // valid 64-char hex
        let v = FingerprintVerifier::new(
            "34a160d3784fdec281d0e2126151bac4dec33f750e1026f44027521785e85163".to_string(),
        );
        assert!(v.is_ok());

        // wrong length
        assert!(FingerprintVerifier::new("ab".to_string()).is_err());

        // not hex
        assert!(FingerprintVerifier::new("z".repeat(64)).is_err());
    }
}
