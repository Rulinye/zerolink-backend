# zerolink-backend — Project Memory

This repo holds TWO independent binaries that work together:

- **Go backend** (root + `cmd/*`) — HTTP API on chuncheon. Listens on `:8080` plaintext (loopback only, `127.0.0.1:8080`) + `:8443` TLS public (self-signed, fingerprint-pinned). Module: `github.com/rulinye/zerolink-backend`.
- **Rust broker** (`broker/`) — WebSocket signaling on `:7842` + QUIC datapath on `:7843`. Crate name: `zerolink-broker`. NOT a Go module — sibling Cargo crate.

They're related but communicate two ways:
1. **Both read the same SQLite DB** at `/var/lib/zerolink-backend/zerolink.db` (production). Go backend is the authoritative writer; broker reads members/rooms via `sqlx::SqlitePool`.
2. **Broker also calls backend over HTTPS** (`reqwest` in `broker/src/verify_client.rs`) for things like service-token verification. URL set via `ZL_BROKER_BACKEND_URL` env var (e.g. `https://168.107.55.126:8443` or `https://127.0.0.1:8443` when broker runs alongside backend).

## ARCHITECTURE OVERVIEW
          ┌──────────────────────────────────────┐
          │   chuncheon (KR Oracle ARM64)        │
          │                                      │
user → :8443 (TLS, fingerprint-pinned) ─→ Go backend (chi)
│                              ↓ writes
│   SQLite (data/zerolink.db)
│                              ↑ reads (sqlx)
client WS → :7842 ──→ Rust broker
client QUIC → :7843 ──→ ┘
│
│   Backend ALSO listens :8080 plain on 127.0.0.1
│   (for SSH tunnel from dev mac, NOT public)
│
│   broker → backend HTTPS via 127.0.0.1:8443 (same host)
└──────────────────────────────────────┘
⤷ broker also deployed on gz (CN)

- Go backend: user CRUD, node management, JWT auth, sing-box config gen, admin endpoints
- Rust broker: room signaling (create/join/leave/destroy via WebSocket) + QUIC datapath for L3 IP relay between room members
- Both deployed via Ansible from `~/code/0-0link-infra/` (NOT from here)

## BUILD & TEST

### Go backend

```bash
make build              # host build (server + admin-create + import-nodes + gen-service-token)
make linux-arm64        # cross-compile for chuncheon (Oracle ARM64)
make linux-amd64        # cross-compile for amd64 (chuncheon is ARM64; rarely needed)
make test               # go test ./...
gofmt -w .              # format BEFORE commit (CI gates on this)
```

CGO_ENABLED=0 always, because `modernc.org/sqlite` is pure Go. Keeps cross-compile clean.

### Rust broker

```bash
cd broker
cargo build --release
cargo test                     # 41+ tests including vswitch + datapath + signaling
cargo fmt
cargo sqlx prepare             # MUST run after changing any sqlx::query!
```

## RUNNING LOCAL DEV

The backend uses env vars, not config files. Defaults are sensible for local dev:

```bash
# Default DB path is /var/lib/zerolink-backend/zerolink.db (production).
# For local dev, point at a local file:
ZL_DB_PATH=./data/dev.db go run .

# More common during phase 3.3 development: SSH-tunnel the production
# backend instead of running locally:
ssh -fN -L 8080:127.0.0.1:8080 oracle
# Now the local 127.0.0.1:8080 reaches chuncheon's backend.
# Client repo's vite proxy assumes this.
```

For broker local dev: see `broker/DEPLOY.md`.

## CONVENTIONS

### Migrations

- Files: `internal/storage/migrations/NNNN_description.{up,down}.sql`
- **`*.down.sql` is no-op for ALTER COLUMN-style schema changes** — modernc SQLite < 3.35 can't ALTER COLUMN. We accept that down-migrations are not fully reversible. Adding columns up-migration: down is no-op.
- After adding a migration: bump the number monotonically, run `ZL_DB_PATH=./data/dev.db go run .` once locally to verify it applies. Never edit a migration that's been applied to production.

### sqlx in broker

- Compile-time SQL verification via offline cache in `broker/.sqlx/*.json`
- After changing any `sqlx::query!` macro: `cd broker; cargo sqlx prepare`
- COMMIT the resulting `.sqlx/*.json` files. CI builds without DB and relies on offline cache.
- See KNOWN-ISSUES B3.3-K5 in client repo.

### Adding a new node

Use `cmd/import-nodes/main.go` — DO NOT INSERT directly into nodes table. The importer normalizes inventory format and handles `broker_enabled` defaulting (D3.36).

### Service tokens

`cmd/gen-service-token` produces broker auth tokens. Run on chuncheon as the `zerolink` user with `backend.env` loaded. Tokens go in vault — see `~/code/0-0link-infra/secrets/vault.yml`, NOT in this repo.

### TLS / fingerprint pinning

Backend serves self-signed TLS on `:8443`. Verification is done by the broker (and clients) via SHA-256 leaf-cert fingerprint pinning, NOT a CA chain. This unifies trust with the broker datapath model (D3.40). Don't try to make the cert "valid" against a CA — it's not the architecture.

The plain `:8080` listener is bound to `127.0.0.1` ONLY. Don't expose it. If you need backend reachable from another machine in dev, use the SSH tunnel pattern above.

## CRITICAL RULES

- DO NOT scp binaries to chuncheon manually. Always deploy via `~/code/0-0link-infra/` Ansible playbooks.
- DO NOT add a Go dependency without my approval.
- DO NOT add a Rust crate to broker without my approval.
- DO NOT run `make build` and assume it produces a chuncheon-compatible binary. Chuncheon is ARM64. The deploy artifact must come from `make linux-arm64`.
- DO NOT edit `.sqlx/*.json` manually. Always regenerate via `cargo sqlx prepare`.
- DO NOT change the auth contract (JWT format, service token format) without checking the client + broker repos. They have hard-coded expectations.
- DO NOT bind `:8080` to anything but `127.0.0.1` in production config.

## KNOWN ISSUES (relevant to this repo)

Most issues are documented in `~/code/0-0link-client/docs/KNOWN-ISSUES.md` — that file is the canonical home for B-numbered issues across the project. Issues touching this repo:

- **B3.3-K5** sqlx offline cache must be committed alongside query changes
- **B3.3-K6** broker `--version` flag not yet implemented; ansible role re-downloads on every run

## CROSS-REPO COORDINATION

- **Production deploy** lives in `~/code/0-0link-infra/` (Ansible). This repo does not deploy.
- **Client / helper** lives in `~/code/0-0link-client/`. Wire format and protocol decisions are in `~/code/0-0link-client/docs/DECISIONS.md`. Adding a new HTTP endpoint usually means updating the client's API client too.
- **Cross-repo architecture** lives in `~/code/0-0link-meta/docs/`.

## WHEN STUCK

Read in this order:
1. This file
2. `~/.claude/CLAUDE.md` (global rules)
3. `~/code/0-0link-client/docs/DECISIONS.md` (D3.* architecture decisions; D3.27, D3.30, D3.36, D3.40 most relevant here)
4. `~/code/0-0link-meta/docs/phase-3-architecture.md`
5. `~/code/0-0link-client/docs/KNOWN-ISSUES.md`
6. `broker/DEPLOY.md` for broker-specific deploy notes
