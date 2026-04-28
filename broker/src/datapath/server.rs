//! QUIC datapath server.
//!
//! # Lifecycle of one connection
//!
//! ## 1. TLS handshake
//!
//! Client opens a QUIC connection on the broker's UDP port (default
//! :7843). rustls validates the client only inasmuch as TLS 1.3
//! forces the handshake; no client cert is requested. The CLIENT
//! validates the broker via SHA-256 fingerprint pinning (the
//! fingerprint was delivered in the WS RPC response).
//!
//! ## 2. Bind frame (client -> broker on bidi stream 0)
//!
//! ```text
//! [u8 version=0x01]
//! [u16 BE session_id_len]
//! [N bytes session_id (utf-8)]
//! ```
//!
//! ## 3. Bind reply (broker -> client on the same stream)
//!
//! Broker validates that the session is in the SessionStore and
//! currently bound to a ws (i.e. not in grace). On success:
//!
//! ```text
//! [u8 status=0x00 OK]
//! [u16 BE assigned_user_id]
//! [u16 BE peer_count]
//! peer_count x [u16 BE user_id]
//! ```
//!
//! On failure:
//!
//! ```text
//! [u8 status != 0x00]
//! [u8 reason]
//! ```
//!
//! Reason codes: 0x01 session_not_found, 0x02 session_in_grace,
//! 0x03 not_in_room, 0x04 protocol_error.
//!
//! ## 4. Steady state
//!
//! Two concurrent tasks run for the connection. The datagram
//! receive loop reads datagrams, expects at least 2 bytes header,
//! looks up `(room_id, dst_user_id)` in PathMap, rewrites the
//! header to `[u16 BE src_user_id]` (this client's user_id), and
//! forwards via the destination's `conn.send_datagram()`. Bytes are
//! counted on both ends.
//!
//! The control-stream RX task drains any inbound bytes from the
//! client side of stream 0. Phase 3.3 has no client-to-broker
//! control messages; the stream is kept open as a liveness signal.
//!
//! ## 5. Connection close
//!
//! On TLS abort, app close, or idle timeout, both tasks observe
//! the close, the path entry is removed, and `peer_removed` is
//! pushed on every other entry's control stream in the same room.

use anyhow::{anyhow, Context};
use bytes::{Buf, BufMut, BytesMut};
use quinn::{Connection, Endpoint, EndpointConfig, RecvStream, SendStream, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use super::cert::DatapathCert;
use super::obfs::{ObfsConfig, ObfsSocket};
use super::path_map::{PathEntry, PathMap};
use crate::ws::session::SessionStore;

const PROTO_VERSION: u8 = 0x01;
const STATUS_OK: u8 = 0x00;
const REASON_SESSION_NOT_FOUND: u8 = 0x01;
const REASON_SESSION_IN_GRACE: u8 = 0x02;
const REASON_NOT_IN_ROOM: u8 = 0x03;
const REASON_PROTOCOL_ERROR: u8 = 0x04;

/// Control-stream message kinds the broker pushes to the client AFTER
/// the bind handshake. All length-prefixed via 1-byte tag + N bytes.
const CTRL_PEER_ADDED: u8 = 0x10;
const CTRL_PEER_REMOVED: u8 = 0x11;

/// Build the quinn ServerConfig for our self-signed datapath cert.
fn make_server_config(cert: &DatapathCert) -> anyhow::Result<ServerConfig> {
    let cert_der = CertificateDer::from(cert.cert_der.clone());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_der.clone()));

    let mut config = ServerConfig::with_single_cert(vec![cert_der], key_der)
        .context("ServerConfig::with_single_cert")?;

    // Reasonable defaults for a datapath:
    //   - keep_alive every 10s so dead peers are reaped within ~30s
    //   - 60s idle timeout matches the same window
    //   - allow datagram extension (RFC 9221) — it's the whole point
    let mut transport = quinn::TransportConfig::default();
    transport
        .keep_alive_interval(Some(std::time::Duration::from_secs(10)))
        .max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(std::time::Duration::from_secs(60))
                .context("idle timeout")?,
        ));
    transport.datagram_receive_buffer_size(Some(2 * 1024 * 1024));
    transport.datagram_send_buffer_size(2 * 1024 * 1024);
    config.transport_config(Arc::new(transport));

    Ok(config)
}

pub struct DatapathServer {
    pub endpoint: Endpoint,
    pub paths: PathMap,
}

pub fn start(
    listen: SocketAddr,
    cert: &DatapathCert,
    sessions: SessionStore,
    obfs: ObfsConfig,
) -> anyhow::Result<DatapathServer> {
    let config = make_server_config(cert)?;
    // D4.2 Phase 4.1: wrap the UDP socket with the salamander-style XOR
    // obfuscator. quinn talks to the wrapper as if it were a regular
    // socket; per-packet XOR happens transparently below quinn.
    let obfs_socket = ObfsSocket::bind(listen, obfs).context("bind obfs UDP socket")?;
    let runtime =
        quinn::default_runtime().ok_or_else(|| anyhow!("no quinn runtime (need tokio)"))?;
    let endpoint = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        Some(config),
        Arc::new(obfs_socket),
        runtime,
    )
    .context("quinn endpoint with obfs socket")?;
    let paths = PathMap::new();

    let acc_paths = paths.clone();
    let acc_sessions = sessions.clone();
    let acc_endpoint = endpoint.clone();
    tokio::spawn(async move {
        accept_loop(acc_endpoint, acc_paths, acc_sessions).await;
    });

    Ok(DatapathServer { endpoint, paths })
}

async fn accept_loop(endpoint: Endpoint, paths: PathMap, sessions: SessionStore) {
    while let Some(incoming) = endpoint.accept().await {
        let paths = paths.clone();
        let sessions = sessions.clone();
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    debug!(target: "datapath", err = %e, "incoming handshake failed");
                    return;
                }
            };
            if let Err(e) = handle_connection(conn, paths, sessions).await {
                debug!(target: "datapath", err = %e, "connection task ended");
            }
        });
    }
}

async fn handle_connection(
    conn: Connection,
    paths: PathMap,
    sessions: SessionStore,
) -> anyhow::Result<()> {
    let remote = conn.remote_address();

    // Step 1: accept the client's control stream (bidi 0).
    let (mut send, mut recv) = conn
        .accept_bi()
        .await
        .context("expected client to open control stream")?;

    // Step 2: read bind frame.
    let bind = match read_bind_frame(&mut recv).await {
        Ok(b) => b,
        Err(e) => {
            warn!(target: "datapath", %remote, err = %e, "bind frame read failed");
            let _ = send_status(&mut send, REASON_PROTOCOL_ERROR).await;
            conn.close(quinn::VarInt::from_u32(0x40), b"bad_bind");
            return Err(e);
        }
    };

    // Step 3: validate session.
    let session = match sessions.find_by_session_id(&bind.session_id).await {
        Some(s) => s,
        None => {
            let _ = send_status(&mut send, REASON_SESSION_NOT_FOUND).await;
            conn.close(quinn::VarInt::from_u32(0x41), b"session_not_found");
            return Ok(());
        }
    };
    // We deliberately allow bind even when the session is in grace
    // (bound_ws.is_none() but the 30s window has not elapsed). The B2
    // grace mechanism is about the WS signalling channel; the QUIC
    // datapath should remain usable for in-flight tunnels through
    // brief WS disconnections (network blips, mobile handoffs). If
    // the session has already been finalized by the watchdog the
    // find_by_session_id call above returns None and we reject.
    let _ = REASON_SESSION_IN_GRACE; // retained as a reserved code
    let room_id = session.room_id;
    let user_id = session.user_id;
    let username = session.username.clone();

    // Build the path entry, then announce ourselves.
    let entry = Arc::new(PathEntry {
        room_id,
        user_id,
        username: username.clone(),
        conn: conn.clone(),
        control_send: Mutex::new(send),
        bytes_in: 0.into(),
        bytes_out: 0.into(),
    });

    // Snapshot existing peers BEFORE inserting ourselves.
    let existing = paths.list_room(room_id).await;
    let _ = paths.insert(entry.clone()).await;

    // Step 4: write bind OK + peer list to ourselves on the control
    // stream (we still own the SendStream via the entry's mutex).
    {
        let mut s = entry.control_send.lock().await;
        if let Err(e) = write_bind_ok(&mut s, user_id, &existing).await {
            warn!(target: "datapath", %remote, err = %e, "bind ok write failed");
            paths.remove(room_id, user_id).await;
            conn.close(quinn::VarInt::from_u32(0x43), b"bind_ok_write_failed");
            return Err(e);
        }
    }

    // Step 5: announce ourselves to peers via their control streams.
    for peer in &existing {
        let mut s = peer.control_send.lock().await;
        if let Err(e) = write_ctrl_peer_event(&mut s, CTRL_PEER_ADDED, user_id).await {
            debug!(
                target: "datapath",
                err = %e,
                peer_user_id = peer.user_id,
                "peer_added announce failed"
            );
        }
    }

    info!(
        target: "datapath",
        %remote,
        user_id,
        username = %username,
        room_id,
        peers = existing.len(),
        "datapath bound"
    );

    // Step 6: spawn the recv-control sink (drops bytes; just a
    // liveness signal) and the datagram forwarder.
    let entry_recv = entry.clone();
    let recv_task = tokio::spawn(async move {
        consume_control_recv(recv, entry_recv).await;
    });

    let forward_paths = paths.clone();
    let forward_entry = entry.clone();
    let forward_task = tokio::spawn(async move {
        if let Err(e) = forward_loop(forward_entry, forward_paths).await {
            debug!(target: "datapath", err = %e, "forward loop ended");
        }
    });

    // Wait for either to finish (typically the connection close).
    tokio::select! {
        _ = recv_task => {},
        _ = forward_task => {},
    }

    // Cleanup.
    paths.remove(room_id, user_id).await;
    let remaining = paths.list_room(room_id).await;
    for peer in &remaining {
        let mut s = peer.control_send.lock().await;
        let _ = write_ctrl_peer_event(&mut s, CTRL_PEER_REMOVED, user_id).await;
    }

    info!(
        target: "datapath",
        %remote,
        user_id,
        username = %username,
        room_id,
        bytes_in = entry.bytes_in.load(std::sync::atomic::Ordering::Relaxed),
        bytes_out = entry.bytes_out.load(std::sync::atomic::Ordering::Relaxed),
        "datapath closed"
    );
    Ok(())
}

// ---------- frame helpers ----------

#[derive(Debug)]
struct BindFrame {
    session_id: String,
}

async fn read_bind_frame(recv: &mut RecvStream) -> anyhow::Result<BindFrame> {
    let mut header = [0u8; 3];
    recv.read_exact(&mut header)
        .await
        .context("read bind header")?;
    if header[0] != PROTO_VERSION {
        return Err(anyhow!("unsupported protocol version {}", header[0]));
    }
    let len = u16::from_be_bytes([header[1], header[2]]) as usize;
    if len == 0 || len > 256 {
        return Err(anyhow!("invalid session_id_len {len}"));
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await.context("read session_id")?;
    let session_id = String::from_utf8(buf).context("session_id is not utf-8")?;
    Ok(BindFrame { session_id })
}

async fn send_status(send: &mut SendStream, reason: u8) -> anyhow::Result<()> {
    let mut buf = BytesMut::with_capacity(2);
    buf.put_u8(0xFF); // any non-zero status indicates error
    buf.put_u8(reason);
    send.write_all(&buf).await.context("write status")?;
    let _ = send.finish();
    Ok(())
}

async fn write_bind_ok(
    send: &mut SendStream,
    assigned_user_id: i64,
    existing_peers: &[Arc<PathEntry>],
) -> anyhow::Result<()> {
    let mut buf = BytesMut::with_capacity(5 + existing_peers.len() * 2);
    buf.put_u8(STATUS_OK);
    buf.put_u16(clamp_user_id(assigned_user_id));
    buf.put_u16(existing_peers.len() as u16);
    for p in existing_peers {
        buf.put_u16(clamp_user_id(p.user_id));
    }
    send.write_all(&buf).await.context("write bind ok")?;
    Ok(())
}

async fn write_ctrl_peer_event(send: &mut SendStream, tag: u8, user_id: i64) -> anyhow::Result<()> {
    let mut buf = BytesMut::with_capacity(3);
    buf.put_u8(tag);
    buf.put_u16(clamp_user_id(user_id));
    send.write_all(&buf).await.context("write ctrl event")?;
    Ok(())
}

fn clamp_user_id(uid: i64) -> u16 {
    // user_ids comfortably fit in u16 for 3.3 (single-user-per-broker
    // dev, room <=65535 members). G6 will widen this when we cross
    // the boundary.
    if uid < 0 || uid > u16::MAX as i64 {
        0
    } else {
        uid as u16
    }
}

// ---------- steady-state tasks ----------

/// Drains the client's control-stream send half. We don't expect
/// any client-to-broker control messages in 3.3, so anything we
/// read is logged and discarded.
async fn consume_control_recv(mut recv: RecvStream, entry: Arc<PathEntry>) {
    let mut scratch = [0u8; 256];
    loop {
        match recv.read(&mut scratch).await {
            Ok(Some(n)) => {
                debug!(
                    target: "datapath",
                    user_id = entry.user_id,
                    n,
                    "ignoring inbound control stream bytes (3.3 has no client→broker ctrl messages)"
                );
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
}

async fn forward_loop(entry: Arc<PathEntry>, paths: PathMap) -> anyhow::Result<()> {
    loop {
        let datagram = match entry.conn.read_datagram().await {
            Ok(d) => d,
            Err(quinn::ConnectionError::ApplicationClosed(_))
            | Err(quinn::ConnectionError::ConnectionClosed(_))
            | Err(quinn::ConnectionError::Reset)
            | Err(quinn::ConnectionError::TimedOut)
            | Err(quinn::ConnectionError::LocallyClosed) => return Ok(()),
            Err(e) => return Err(e.into()),
        };

        if datagram.len() < 2 {
            // malformed; drop silently
            continue;
        }
        entry.add_in(datagram.len() as u64);

        let mut cursor = datagram.clone();
        let dst_user_id = cursor.get_u16() as i64;

        // Look up destination in the same room.
        let dest = match paths.get(entry.room_id, dst_user_id).await {
            Some(d) => d,
            None => continue, // peer offline; drop
        };
        if dest.user_id == entry.user_id {
            continue; // sending to self; drop
        }

        // Rewrite header: replace dst with src (this client's user_id).
        let payload_len = datagram.len() - 2;
        let mut out = BytesMut::with_capacity(2 + payload_len);
        out.put_u16(clamp_user_id(entry.user_id));
        out.extend_from_slice(&cursor[..payload_len]);

        let out_bytes = out.freeze();
        let out_len = out_bytes.len() as u64;
        match dest.conn.send_datagram(out_bytes) {
            Ok(()) => {
                dest.add_out(out_len);
            }
            Err(e) => {
                debug!(
                    target: "datapath",
                    err = %e,
                    src_user_id = entry.user_id,
                    dst_user_id,
                    "send_datagram failed (peer connection unhealthy)"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_user_id_in_range() {
        assert_eq!(clamp_user_id(0), 0);
        assert_eq!(clamp_user_id(1), 1);
        assert_eq!(clamp_user_id(65535), 65535);
    }

    #[test]
    fn clamp_user_id_out_of_range_returns_zero() {
        assert_eq!(clamp_user_id(-1), 0);
        assert_eq!(clamp_user_id(70000), 0);
    }
}
