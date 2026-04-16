# zerolink-backend

> The control-plane HTTP service for the 0-0link project.
> Phase 1: invite-based registration, JWT sessions, node listing,
> Clash-compatible subscription links, minimal admin web UI.

## Quick reference

| Endpoint | Auth | What it does |
|---|---|---|
| `GET /ping` | none | health check |
| `GET /version` | none | returns build version |
| `GET /sub/{token}` | token = credential | Clash YAML subscription |
| `POST /api/v1/auth/register` | invite code | create new user |
| `POST /api/v1/auth/login` | none | get JWT |
| `GET /api/v1/auth/me` | jwt | current user |
| `POST /api/v1/auth/logout` | jwt | revoke current jti |
| `GET /api/v1/nodes` | jwt | list enabled nodes |
| `GET /api/v1/nodes/{id}/config` | jwt | full client params |
| `GET /api/v1/subscriptions` | jwt | list your subs |
| `POST /api/v1/subscriptions` | jwt | create new sub token |
| `DELETE /api/v1/subscriptions/{token}` | jwt | revoke sub |
| `GET /api/v1/admin/users` | jwt + admin | user list |
| `POST /api/v1/admin/users/{id}/disable` | jwt + admin | enable/disable user |
| `GET /api/v1/admin/invites` | jwt + admin | list invites |
| `POST /api/v1/admin/invites` | jwt + admin | mint 1..50 invites |
| `GET /api/v1/admin/nodes` | jwt + admin | full node list incl. config_json |
| `GET /admin/*` | cookie | HTML admin UI |

## Environment

All config is via env vars, read by `internal/config`:

| Var | Default | Notes |
|---|---|---|
| `ZL_LISTEN` | `127.0.0.1:8080` | listen addr |
| `ZL_DB_PATH` | `/var/lib/zerolink-backend/zerolink.db` | SQLite file |
| `ZL_JWT_SECRET` | **required** | >=32 bytes |
| `ZL_JWT_TTL` | `168h` | access token TTL (Go duration) |
| `ZL_JWT_ISSUER` | `zerolink-backend` | JWT `iss` claim |
| `ZL_ADMIN_UI` | `true` | toggle `/admin/*` |
| `ZL_LOG_JSON` | `true` | JSON vs text slog handler |

## Local dev

```bash
make build           # compile to ./bin/
make test            # go test -race ./...
make run             # starts on 127.0.0.1:8080 with a dev DB in ./dev/
make linux-amd64     # cross-compile for production (also: linux-arm64)
make lint            # gofmt + go vet
```

`make run` generates a throwaway 32-byte JWT secret for each launch.

## First admin user

The deploy creates **no users automatically**. After the playbook finishes:

```bash
ssh ubuntu@<host>
sudo -u zerolink /usr/local/bin/zerolink-backend-admin-create -u rulinye
```

Once an admin exists, mint invite codes via `POST /api/v1/admin/invites` (or
through `/admin/invites` in the browser) and share them with users.

## Project layout

```
.
├── main.go                              # bootstrap: config → DB → server
├── go.mod / go.sum
├── Makefile
├── .github/workflows/build.yml          # CI: test → matrix amd64/arm64 → release
├── cmd/
│   ├── admin-create/                    # CLI: create or reset an admin
│   └── import-nodes/                    # CLI: sync nodes table from JSON
├── internal/
│   ├── config/                          # env-var driven Config
│   ├── storage/                         # SQLite, migrations, repos
│   │   └── migrations/                  # 0001_init.{up,down}.sql
│   ├── auth/                            # bcrypt + JWT + middleware
│   ├── server/                          # HTTP handlers, routing, admin UI
│   └── clash/                           # Clash YAML subscription renderer
└── web/
    ├── templates/                       # HTML for /admin/*
    └── static/                          # CSS
```

## Deviations from the original plan

- **No `golang-migrate/migrate`.** With one migration file and zero schema
  diffs in flight, a 30-line handwritten runner (`internal/storage/db.go`)
  reads `migrations/*.up.sql` from `embed.FS` in lexical order and tracks
  applied versions in `schema_migrations`. The table layout matches what
  golang-migrate uses, so swapping in is trivial when Phase 4 introduces
  schema diffs.

- **No ORM.** All SQL is hand-written, parameterized via `database/sql`.
  See `internal/storage/users.go` for the pattern.

- **No HTML layout/partial templates.** Each `web/templates/*.html` is a
  full document with copy-pasted nav. The admin UI is small enough that
  keeping each page self-contained is less mental overhead than fighting
  `html/template`'s `define`/`template` semantics.

## Phase 1 deliverable

See [`docs/phase-1-completion.md`](../docs/phase-1-completion.md) for the
full report, decision log, known issues, and Phase 2 handover.
