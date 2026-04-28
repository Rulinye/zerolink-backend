//! UDP-level salamander-style obfuscation wrapper for the QUIC datapath.
//!
//! Per Phase 4.1 D4.2 (in `0-0link-client/docs/DECISIONS.md`):
//!
//!   - Each outbound UDP packet is prefixed with an 8-byte random salt
//!     and XORed against a 32-byte keystream derived from
//!     SHA-256(salt || preshared_password). The keystream cycles every
//!     32 bytes for the full packet length. Inbound packets are decoded
//!     by reversing the same operation.
//!
//!   - The wrapper is plugged into quinn via
//!     `Endpoint::new_with_abstract_socket(EndpointConfig, Some(server),
//!     Arc::new(ObfsSocket::bind(addr, obfs)), runtime)`. Quinn talks to
//!     `ObfsSocket` exactly as it would talk to a regular UDP socket; the
//!     XOR happens transparently at the UDP layer below QUIC.
//!
//!   - GFW sees a stream of pseudo-random UDP datagrams with an 8-byte
//!     changing prefix per packet — no SNI to match (the QUIC Initial
//!     packet's CRYPTO frames carrying the TLS ClientHello are
//!     XOR-scrambled before they leave our process), no QUIC-specific
//!     header signature.
//!
//! ## Per-packet cost
//!
//!   - 1 SHA-256 of (8-byte salt + password bytes) — ~80 ns on Apple Silicon
//!   - XOR over 1500-byte MTU cycling a 32-byte keystream — ~200 ns
//!     SIMD-vectorized
//!   - Total ≈ 300 ns / packet — three orders of magnitude under Phase 4
//!     hard constraint 1's 1 ms budget. At the broker's expected
//!     ~100 Mbit/s ceiling that is ~0.24% CPU per core, effectively free.
//!
//!   - Wire overhead = 8 bytes / packet ≈ 0.5% bandwidth tax at 1500 MTU.
//!
//! ## Single-packet path
//!
//!   - `max_transmit_segments = 1` and `max_receive_segments = 1` disable
//!     GSO / GRO batching. The XOR transform is bytewise, not segment-
//!     boundary-aware, so we always handle one packet at a time. Throughput
//!     ceiling for our use is far below where GSO/GRO would matter.
//!
//! ## Mirror module
//!
//!   - The client-side mirror at `0-0link-client/src-tauri/src/datapath/obfs.rs`
//!     uses the SAME algorithm with the SAME password, so the broker and any
//!     client interoperate. The shared password is distributed via
//!     deployment (vault → broker.env, compiled-into client per batch 4.8).
//!
//! ## Threat model note
//!
//!   - The XOR provides obfuscation, NOT cryptographic confidentiality. TLS
//!     1.3 inside the QUIC connection (rustls + our existing
//!     fingerprint-pinning verifier) provides the actual confidentiality and
//!     authentication. A leaked password lets GFW de-XOR our packets back to
//!     plain QUIC; that is the SAME state we are in today (no obfuscation
//!     at all). It does not weaken authentication.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::io::ReadBuf;

const SALT_LEN: usize = 8;
const KEYSTREAM_LEN: usize = 32; // SHA-256 output

/// Shared obfuscation parameters. Cheap to clone (Arc'd password).
#[derive(Clone)]
pub struct ObfsConfig {
    password: Arc<Vec<u8>>,
}

impl ObfsConfig {
    /// Construct from a non-empty password. Panics on empty input — the
    /// caller is responsible for surfacing missing config as a startup
    /// error before reaching this point.
    pub fn new(password: impl Into<Vec<u8>>) -> Self {
        let p: Vec<u8> = password.into();
        assert!(!p.is_empty(), "ObfsConfig: password must be non-empty");
        Self {
            password: Arc::new(p),
        }
    }

    /// Compute the keystream for a given salt.
    fn derive_keystream(&self, salt: &[u8; SALT_LEN]) -> [u8; KEYSTREAM_LEN] {
        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.update(&*self.password);
        let digest = hasher.finalize();
        let mut ks = [0u8; KEYSTREAM_LEN];
        ks.copy_from_slice(&digest[..]);
        ks
    }
}

/// Pure salamander-style XOR transform. Out-of-place; caller owns the
/// destination buffer. Returns nothing — encoding/decoding is symmetric.
fn xor_in_place(buf: &mut [u8], keystream: &[u8; KEYSTREAM_LEN]) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b ^= keystream[i % KEYSTREAM_LEN];
    }
}

pub struct ObfsSocket {
    inner: tokio::net::UdpSocket,
    obfs: ObfsConfig,
}

impl fmt::Debug for ObfsSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObfsSocket")
            .field("local_addr", &self.inner.local_addr().ok())
            .finish()
    }
}

impl ObfsSocket {
    /// Bind a UDP socket on `addr` and wrap it with the given obfs config.
    pub fn bind(addr: SocketAddr, obfs: ObfsConfig) -> io::Result<Self> {
        let socket = std::net::UdpSocket::bind(addr)?;
        socket.set_nonblocking(true)?;
        let inner = tokio::net::UdpSocket::from_std(socket)?;
        Ok(Self { inner, obfs })
    }
}

impl AsyncUdpSocket for ObfsSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(ObfsPoller { socket: self })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        // Encode: [8-byte salt][XOR(packet, keystream)]
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let ks = self.obfs.derive_keystream(&salt);

        let mut wire = Vec::with_capacity(SALT_LEN + transmit.contents.len());
        wire.extend_from_slice(&salt);
        wire.extend_from_slice(transmit.contents);
        // XOR only the payload portion (after the salt prefix)
        xor_in_place(&mut wire[SALT_LEN..], &ks);

        // Tokio's try_send_to returns WouldBlock when the socket buffer is full,
        // matching what quinn expects from try_send.
        self.inner
            .try_send_to(&wire, transmit.destination)
            .map(|_| ())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Read into a staging buffer, then decode + copy into bufs[0].
        // 65535 is the maximum UDP datagram size; QUIC packets are well
        // below this, but we size for the worst case to avoid truncation.
        let mut staging = [0u8; 65535];
        let mut read_buf = ReadBuf::new(&mut staging);

        let from = match self.inner.poll_recv_from(cx, &mut read_buf) {
            Poll::Ready(Ok(addr)) => addr,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        };

        let received = read_buf.filled();
        if received.len() < SALT_LEN {
            // Bogus / truncated packet — drop silently. quinn treats
            // `Ok(0)` as "no datagram delivered this poll" and will
            // re-poll on the next wake.
            return Poll::Ready(Ok(0));
        }

        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&received[..SALT_LEN]);
        let payload = &received[SALT_LEN..];
        let ks = self.obfs.derive_keystream(&salt);

        let dest = &mut bufs[0];
        let copy_len = payload.len().min(dest.len());
        for i in 0..copy_len {
            dest[i] = payload[i] ^ ks[i % KEYSTREAM_LEN];
        }

        meta[0] = RecvMeta {
            addr: from,
            len: copy_len,
            stride: copy_len,
            ecn: None,
            dst_ip: None,
        };

        Poll::Ready(Ok(1))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        // GSO would batch multiple segments into one syscall; our XOR
        // transform is per-packet, so we explicitly disable.
        1
    }

    fn max_receive_segments(&self) -> usize {
        // GRO would deliver multiple segments in one buffer; same reason.
        1
    }
}

#[derive(Debug)]
struct ObfsPoller {
    socket: Arc<ObfsSocket>,
}

impl UdpPoller for ObfsPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Forward to the underlying tokio UDP socket's writability check.
        self.socket.inner.poll_send_ready(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keystream_roundtrip() {
        let cfg = ObfsConfig::new(b"a-test-password-not-used-in-prod".to_vec());
        let salt = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let ks = cfg.derive_keystream(&salt);
        let plain = b"hello world this is a quic packet payload, longer than 32 bytes for sure";
        let mut cipher = plain.to_vec();
        xor_in_place(&mut cipher, &ks);
        assert_ne!(&cipher, plain);
        let mut decrypted = cipher.clone();
        xor_in_place(&mut decrypted, &ks);
        assert_eq!(&decrypted, plain);
    }

    #[test]
    fn keystream_differs_per_salt() {
        let cfg = ObfsConfig::new(b"password".to_vec());
        let s1 = [0u8; SALT_LEN];
        let s2 = [1u8; SALT_LEN];
        assert_ne!(cfg.derive_keystream(&s1), cfg.derive_keystream(&s2));
    }

    #[test]
    fn keystream_differs_per_password() {
        let a = ObfsConfig::new(b"alpha".to_vec());
        let b = ObfsConfig::new(b"bravo".to_vec());
        let salt = [42u8; SALT_LEN];
        assert_ne!(a.derive_keystream(&salt), b.derive_keystream(&salt));
    }

    #[test]
    #[should_panic(expected = "password must be non-empty")]
    fn empty_password_panics() {
        ObfsConfig::new(Vec::new());
    }

    #[test]
    fn keystream_is_deterministic() {
        let cfg = ObfsConfig::new(b"x".to_vec());
        let salt = [9u8; SALT_LEN];
        assert_eq!(cfg.derive_keystream(&salt), cfg.derive_keystream(&salt));
    }
}
