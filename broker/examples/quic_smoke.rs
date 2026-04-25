//! QUIC datapath smoke test.
//!
//! Two-client end-to-end exercise of the broker datapath:
//!   1. Connect to ws://127.0.0.1:7842/rpc/ws as client A, create_room.
//!   2. Connect to ws://127.0.0.1:7842/rpc/ws as client B (same JWT
//!      since we only have rulinye locally — broker rejects this in
//!      normal flow because A3 says one session per user). To work
//!      around the single-user constraint, this smoke test runs
//!      ONLY client A through the full bind handshake. Multi-user
//!      datagram forwarding is left for the real client.
//!   3. Verify the bind frame succeeds: receive [u8 OK][u16 user_id]
//!      [u16 peer_count=0].
//!   4. Send one datagram to a non-existent dst_user_id (peer_count=0
//!      so the datagram is dropped by broker — we don't expect any
//!      reply; we just verify the connection stays up after sending).
//!   5. Close cleanly.
//!
//! Usage:
//!   cargo run --example quic_smoke -- <jwt>
//!
//! Requires the broker to be running locally with:
//!   ZL_BROKER_LISTEN_HTTP=127.0.0.1:7842
//!   ZL_BROKER_LISTEN_QUIC=127.0.0.1:7843

use anyhow::{anyhow, Context, Result};
use bytes::{BufMut, BytesMut};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

const PROTO_VERSION: u8 = 0x01;
const STATUS_OK: u8 = 0x00;

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow!("install rustls crypto provider"))?;

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "usage: {} <jwt>",
            args.first().map(String::as_str).unwrap_or("quic_smoke")
        );
        std::process::exit(2);
    }
    let jwt = args[1].clone();

    // -------- Step 1: WS create_room ---------------------------
    let (session_id, room_id, code, quic_endpoint, quic_fingerprint) =
        ws_create_room(&jwt).await.context("ws create_room")?;
    eprintln!("[ws] create_room ok: room_id={room_id} code={code} session_id={session_id}");
    eprintln!("[ws] quic_endpoint={quic_endpoint} fingerprint={quic_fingerprint}");

    // -------- Step 2: QUIC connect with fingerprint pinning ----
    let server_addr: SocketAddr = quic_endpoint.parse().context("parse quic_endpoint")?;
    let endpoint = build_quic_client(&quic_fingerprint).context("build quic client")?;

    let connection = endpoint
        .connect(server_addr, "127.0.0.1")
        .context("quinn connect()")?
        .await
        .context("await quinn handshake")?;
    eprintln!(
        "[quic] handshake ok, remote={}",
        connection.remote_address()
    );

    // -------- Step 3: open bidi stream, send bind frame --------
    let (mut send, mut recv) = connection.open_bi().await.context("open bidi stream")?;
    let bind = encode_bind_frame(&session_id);
    send.write_all(&bind).await.context("write bind")?;
    eprintln!("[quic] bind frame sent ({} bytes)", bind.len());

    // -------- Step 4: read bind reply --------------------------
    let mut header = [0u8; 5];
    recv.read_exact(&mut header)
        .await
        .context("read bind reply header")?;
    if header[0] != STATUS_OK {
        return Err(anyhow!(
            "bind rejected: status=0x{:02x} reason=0x{:02x}",
            header[0],
            header[1]
        ));
    }
    let assigned_user_id = u16::from_be_bytes([header[1], header[2]]);
    let peer_count = u16::from_be_bytes([header[3], header[4]]);
    eprintln!("[quic] bind OK: assigned_user_id={assigned_user_id} peer_count={peer_count}");
    if peer_count > 0 {
        let mut peers_buf = vec![0u8; peer_count as usize * 2];
        recv.read_exact(&mut peers_buf)
            .await
            .context("read peer list")?;
        for chunk in peers_buf.chunks_exact(2) {
            let pid = u16::from_be_bytes([chunk[0], chunk[1]]);
            eprintln!("[quic]   peer user_id={pid}");
        }
    }

    // -------- Step 5: send a datagram to non-existent peer ----
    // Header: [u16 BE dst_user_id=9999][payload]
    let mut dgram = BytesMut::new();
    dgram.put_u16(9999);
    dgram.extend_from_slice(b"hello-from-smoke-test");
    let dgram = dgram.freeze();
    connection
        .send_datagram(dgram.clone())
        .context("send_datagram")?;
    eprintln!(
        "[quic] sent {} byte datagram (dst=9999, will be dropped)",
        dgram.len()
    );

    // -------- Step 6: brief idle to confirm connection stays up
    tokio::time::sleep(Duration::from_millis(500)).await;
    if let Some(reason) = connection.close_reason() {
        return Err(anyhow!("connection died unexpectedly: {reason:?}"));
    }
    eprintln!("[quic] connection still alive after datagram send");

    // -------- Step 7: clean shutdown ---------------------------
    connection.close(0u32.into(), b"smoke_done");
    endpoint.wait_idle().await;
    eprintln!("[quic] closed cleanly");

    eprintln!();
    eprintln!("✅ QUIC smoke test passed");
    Ok(())
}

// ===== WS plumbing =========================================================

async fn ws_create_room(jwt: &str) -> Result<(String, i64, String, String, String)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    // Hand-rolled minimal WS client: HTTP/1.1 Upgrade, then send one
    // text frame, read one text frame. We don't pull tungstenite as a
    // dev-dependency just for this; the protocol is small.
    let mut stream = TcpStream::connect("127.0.0.1:7842")
        .await
        .context("ws tcp connect")?;
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let req = format!(
        "GET /rpc/ws?jwt={jwt} HTTP/1.1\r\n\
         Host: 127.0.0.1:7842\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         \r\n"
    );
    stream
        .write_all(req.as_bytes())
        .await
        .context("ws write upgrade")?;

    // Read upgrade response (expect 101 Switching Protocols).
    let mut buf = vec![0u8; 4096];
    let n = stream
        .read(&mut buf)
        .await
        .context("ws read upgrade reply")?;
    let head = String::from_utf8_lossy(&buf[..n]);
    if !head.starts_with("HTTP/1.1 101") {
        return Err(anyhow!(
            "ws upgrade failed: {}",
            head.lines().next().unwrap_or("")
        ));
    }

    // Send create_room frame (masked text, fin=1).
    let payload = br#"{"type":"req","id":"smoke","method":"create_room","params":{}}"#;
    let frame = build_ws_text_frame(payload);
    stream.write_all(&frame).await.context("ws write frame")?;

    // Read response frame (server frames are unmasked).
    let mut buf2 = vec![0u8; 4096];
    let n = stream.read(&mut buf2).await.context("ws read response")?;
    let payload = parse_ws_text_frame(&buf2[..n])
        .ok_or_else(|| anyhow!("could not parse ws response frame"))?;
    let body = String::from_utf8_lossy(&payload).to_string();

    let v: serde_json::Value =
        serde_json::from_str(&body).with_context(|| format!("parse RPC response: {body}"))?;
    if let Some(err) = v.get("error") {
        return Err(anyhow!("RPC error: {err}"));
    }
    let r = v
        .get("result")
        .ok_or_else(|| anyhow!("RPC response missing result: {body}"))?;
    let session_id = r
        .get("session_id")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("no session_id"))?
        .to_string();
    let room_id = r
        .get("room_id")
        .and_then(|x| x.as_i64())
        .ok_or_else(|| anyhow!("no room_id"))?;
    let code = r
        .get("code")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("no code"))?
        .to_string();
    let quic_endpoint = r
        .get("quic_endpoint")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("no quic_endpoint"))?
        .to_string();
    let quic_fingerprint = r
        .get("quic_fingerprint")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("no quic_fingerprint"))?
        .to_string();
    Ok((session_id, room_id, code, quic_endpoint, quic_fingerprint))
}

/// Build a single masked text frame with fin=1.
fn build_ws_text_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(0x81); // FIN=1, opcode=text
    let len = payload.len();
    if len < 126 {
        out.push(0x80 | len as u8); // mask=1
    } else if len < 65536 {
        out.push(0x80 | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0x80 | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    let mask = [0x12u8, 0x34, 0x56, 0x78];
    out.extend_from_slice(&mask);
    for (i, b) in payload.iter().enumerate() {
        out.push(b ^ mask[i % 4]);
    }
    out
}

/// Parse a single unmasked text frame from server.
fn parse_ws_text_frame(buf: &[u8]) -> Option<Vec<u8>> {
    if buf.len() < 2 {
        return None;
    }
    let opcode = buf[0] & 0x0f;
    if opcode != 1 {
        return None; // not text
    }
    let masked = (buf[1] & 0x80) != 0;
    let len_byte = buf[1] & 0x7f;
    let (payload_len, mut pos) = if len_byte < 126 {
        (len_byte as usize, 2)
    } else if len_byte == 126 {
        if buf.len() < 4 {
            return None;
        }
        (u16::from_be_bytes([buf[2], buf[3]]) as usize, 4)
    } else {
        if buf.len() < 10 {
            return None;
        }
        (
            u64::from_be_bytes([
                buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
            ]) as usize,
            10,
        )
    };
    let mask = if masked {
        if buf.len() < pos + 4 {
            return None;
        }
        let m = [buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]];
        pos += 4;
        Some(m)
    } else {
        None
    };
    if buf.len() < pos + payload_len {
        return None;
    }
    let mut payload = buf[pos..pos + payload_len].to_vec();
    if let Some(m) = mask {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= m[i % 4];
        }
    }
    Some(payload)
}

// ===== Bind frame ==========================================================

fn encode_bind_frame(session_id: &str) -> Vec<u8> {
    let bytes = session_id.as_bytes();
    let len = bytes.len();
    let mut out = Vec::with_capacity(3 + len);
    out.push(PROTO_VERSION);
    out.extend_from_slice(&(len as u16).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

// ===== Quinn client config (fingerprint pinning) ==========================

fn build_quic_client(expected_fingerprint_hex: &str) -> Result<quinn::Endpoint> {
    let verifier = Arc::new(FingerprintVerifier {
        expected: hex::decode(expected_fingerprint_hex).context("decode fingerprint hex")?,
    });
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(60)).unwrap(),
    ));

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .context("convert rustls config to quinn")?,
    ));
    client_config.transport_config(Arc::new(transport));

    let mut endpoint =
        quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).context("client bind")?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

#[derive(Debug)]
struct FingerprintVerifier {
    expected: Vec<u8>,
}

impl ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let mut h = Sha256::new();
        h.update(end_entity.as_ref());
        let actual = h.finalize();
        if actual.as_slice() == self.expected.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("fingerprint mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
        ]
    }
}
