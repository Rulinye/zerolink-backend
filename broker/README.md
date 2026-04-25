# zerolink-broker

Rust crate co-located with the Go backend in this repo. Runs on each
broker-capable node (currently chuncheon; gz follows in batch 3.3 group 3).

## What it does

In Phase 3 batch 3.3 the broker provides:

1. **Room signaling** (HTTP + WebSocket): clients create / join / leave
   rooms and receive push events about member changes.
2. **L3 datapath relay** (QUIC): clients tunnel raw IP packets through
   the broker to reach each other when direct P2P isn't available
   (which is always, in 3.3 — P2P arrives in 4.1).

Backend authoritative checks (user identity, quota, disabled state)
are performed by reverse-verifying client JWTs against backend's
`/api/v1/auth/verify` endpoint, with the broker holding a Bearer
service token issued via backend's `gen-service-token` CLI. TLS to the
backend uses **leaf-cert sha256 fingerprint pinning**, not CA chain
validation — see `src/verify_client.rs` for the rustls
`ServerCertVerifier` implementation.

## Local development

```bash
cd broker

# All required env vars set inline (replace fingerprint + service token
# with values for whatever backend you're targeting).
ZL_BROKER_BACKEND_URL=https://168.107.55.126:8443 \
ZL_BROKER_BACKEND_FINGERPRINT=34a160d3784fdec281d0e2126151bac4dec33f750e1026f44027521785e85163 \
ZL_BROKER_SERVICE_TOKEN=<paste plaintext from gen-service-token> \
ZL_BROKER_SHORT_ID=KR \
ZL_BROKER_LISTEN_HTTP=127.0.0.1:7842 \
ZL_BROKER_LISTEN_QUIC=127.0.0.1:7843 \
ZL_BROKER_DB_PATH=/tmp/broker-dev.db \
ZL_BROKER_LOG_JSON=false \
cargo run

# Verify in another terminal:
curl -s http://127.0.0.1:7842/ping
curl -s http://127.0.0.1:7842/version
```

The DB path is referenced now but only used in 2b+. The QUIC listen
address is referenced now but only bound in 2d+.

## Building

```bash
cargo build --release   # ./target/release/zerolink-broker
cargo test              # unit tests
cargo fmt --check
cargo clippy -- -D warnings
```

## Configuration

All knobs are env vars, prefix `ZL_BROKER_*`. See `src/config.rs` for
the full list with defaults. Required vars:

- `ZL_BROKER_SERVICE_TOKEN` — Bearer token, from backend
  `gen-service-token --label broker-<short_id>`.
- `ZL_BROKER_BACKEND_FINGERPRINT` — sha256 hex of the backend's leaf
  cert (lowercase, no separators). Operator-supplied via Ansible
  vault.
- `ZL_BROKER_SHORT_ID` — 2-3 char alphanumeric (e.g. `KR`, `GZ`).
  Globally unique among brokers; used as the prefix in room codes
  (`KR-XK7P9R`).

## Layout

```
broker/
├── Cargo.toml
├── README.md
├── migrations/        ← 2b: rooms, members, traffic
└── src/
    ├── main.rs        ← bootstrap, signal handling
    ├── config.rs      ← env-driven config
    ├── verify_client.rs ← reverse-verify backend with fingerprint pin
    └── http.rs        ← axum router (/ping, /version, …)
```

## Sub-commit roadmap (batch 3.3 group 2)

- **2a (this commit)**: skeleton — config, verify client + cache,
  HTTP /ping /version.
- **2b**: SQLite (rooms, members, traffic) via sqlx + offline
  migrations. `sqlx-data.json` checked into git.
- **2c**: WebSocket signaling RPC (create_room / join_room / etc.) +
  push events (member_joined, etc.).
- **2d**: QUIC datapath listener + L3 forwarding loop.
- **2e**: dev-mode deployment to chuncheon — manual scp + systemd
  unit. Full Ansible role lands in group 3.
