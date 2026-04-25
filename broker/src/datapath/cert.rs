//! Self-signed TLS certificate for the QUIC datapath.
//!
//! On every broker startup we generate a fresh ed25519 keypair and a
//! self-signed certificate covering the broker's external host. The
//! SHA-256 fingerprint of the DER-encoded cert is the only piece of
//! information clients need to authenticate the connection — they
//! receive it inside the WS RPC response (e.g. `create_room` returns
//! `quic_fingerprint`) and pin it during the QUIC handshake.
//!
//! No CA chain, no domain name verification, no certificate transparency.
//! This is the same fingerprint-pinning model we use for the
//! broker → backend reverse-verify path.
//!
//! Why ed25519:
//!   - small certs and keys (broker process memory)
//!   - rustls supports it natively
//!   - quinn supports it natively
//!
//! Why fresh cert per restart:
//!   - no on-disk private key to manage / rotate / leak
//!   - WS clients must reconnect after a broker restart anyway, so
//!     they pick up the fresh fingerprint with zero ceremony
//!   - the cost is one ed25519 keygen per broker boot (microseconds)

use anyhow::Context;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ED25519};
use sha2::{Digest, Sha256};

pub struct DatapathCert {
    /// DER-encoded certificate, as quinn / rustls expect.
    pub cert_der: Vec<u8>,
    /// PKCS#8 DER-encoded private key.
    pub key_der: Vec<u8>,
    /// Lowercase hex SHA-256 of `cert_der`. Clients pin this.
    pub fingerprint_hex: String,
}

pub fn generate(external_host: &str) -> anyhow::Result<DatapathCert> {
    let mut params =
        CertificateParams::new(vec![external_host.to_string()]).context("init cert params")?;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "zerolink-broker-datapath");
    params.distinguished_name = dn;

    let key_pair = KeyPair::generate_for(&PKCS_ED25519).context("generate ed25519 keypair")?;
    let cert = params.self_signed(&key_pair).context("self-sign cert")?;

    let cert_der = cert.der().to_vec();
    let key_der = key_pair.serialize_der();

    let mut hasher = Sha256::new();
    hasher.update(&cert_der);
    let fp = hasher.finalize();
    let fingerprint_hex = hex::encode(fp);

    Ok(DatapathCert {
        cert_der,
        key_der,
        fingerprint_hex,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_has_64char_hex_fingerprint() {
        let c = generate("127.0.0.1").unwrap();
        assert_eq!(c.fingerprint_hex.len(), 64);
        assert!(c.fingerprint_hex.chars().all(|x| x.is_ascii_hexdigit()));
        assert!(!c.cert_der.is_empty());
        assert!(!c.key_der.is_empty());
    }

    #[test]
    fn fresh_cert_each_call() {
        let a = generate("127.0.0.1").unwrap();
        let b = generate("127.0.0.1").unwrap();
        assert_ne!(a.fingerprint_hex, b.fingerprint_hex);
    }
}
