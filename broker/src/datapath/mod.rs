//! QUIC datapath: room-mate L3 tunnel relay over QUIC datagrams.
//!
//! See `server.rs` for the wire protocol. See `cert.rs` for the
//! self-signed-cert + fingerprint-pinning trust model. See
//! `path_map.rs` for the routing table.

pub mod cert;
pub mod path_map;
pub mod server;

pub use cert::generate as generate_cert;
pub use path_map::PathMap;
pub use server::start as start_server;

/// Information the WS layer needs to give clients in
/// create_room/join_room/resume_session responses so they can
/// connect to the datapath.
#[derive(Clone)]
pub struct DatapathInfo {
    /// Externally reachable host:port that clients should QUIC-connect to.
    /// In dev this is loopback; in prod it's the broker's public IP.
    pub endpoint: String,
    /// SHA-256 fingerprint of the broker's QUIC TLS cert. Lowercase hex.
    pub fingerprint: String,
}
