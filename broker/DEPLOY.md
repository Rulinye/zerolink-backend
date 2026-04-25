# broker — manual deployment runbook

Reference for deploying `zerolink-broker` to a new host. Used for the
chuncheon (KR) production rollout in Phase 3 batch 3.3 group 2e.
Phase 3 batch 3.3 group 3 will replace this with an Ansible role; this
document records the exact steps that role needs to reproduce.

## Prerequisites on the host

- Linux x86_64 or aarch64. Tested on Ubuntu 22.04 ARM64 (Oracle Cloud
  Always Free Ampere A1).
- A working `zerolink-backend` instance reachable from the host. The
  broker reverse-verifies every JWT against backend, so backend must
  be up and its TLS leaf certificate fingerprint must be known.
- A `zerolink` system user (the broker runs as this user; it is the
  same user the backend runs as on the same host).

## 1. Build the binary

Native compile on the host (the binary is ~8 MB; cargo build takes
2 to 15 minutes depending on the host's core count).

```sh
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev libsqlite3-dev
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env

sudo mkdir -p /opt/build
sudo chown $USER /opt/build
cd /opt/build
git clone git@github.com:Rulinye/zerolink-backend.git
cd zerolink-backend
git checkout phase-3-batch-3.3
cd broker
SQLX_OFFLINE=true cargo build --release
```

Cross-compiling from macOS to Linux ARM64 is technically possible but
in practice the linker setup is fragile; native compilation on the
host is faster and gives the same result.

## 2. Install paths

```sh
sudo cp target/release/zerolink-broker /usr/local/bin/
sudo chmod 755 /usr/local/bin/zerolink-broker

sudo mkdir -p /var/lib/zerolink-broker
sudo chown zerolink:zerolink /var/lib/zerolink-broker
sudo chmod 750 /var/lib/zerolink-broker

sudo mkdir -p /etc/zerolink-broker
sudo chown root:zerolink /etc/zerolink-broker
sudo chmod 750 /etc/zerolink-broker
```

## 3. Service token

Each broker has its own service token, minted by the backend's
`gen-service-token` CLI and stored in plaintext only in the broker's
env file. Tokens are random 256-bit values; the backend stores
SHA-256 hashes only and rejects unknown tokens with HTTP 401.

Generate on the backend host:

```sh
sudo bash -c '
  set -a
  source /etc/zerolink-backend/backend.env
  set +a
  sudo -u zerolink -E /usr/local/bin/zerolink-backend-gen-service-token -label broker-<id>-<env>
'
```

Replace `<id>-<env>` with e.g. `kr-prod` or `gz-staging`. The CLI
prints the plaintext token exactly once. Save it to a secure
password manager and to the broker's env file in step 4.

To rotate, generate a new token, deploy to the broker, restart, and
disable the old token:

```sh
sudo bash -c '
  set -a
  source /etc/zerolink-backend/backend.env
  set +a
  sudo -u zerolink -E /usr/local/bin/zerolink-backend-gen-service-token -list
'
sudo bash -c '
  set -a
  source /etc/zerolink-backend/backend.env
  set +a
  sudo -u zerolink -E /usr/local/bin/zerolink-backend-gen-service-token -disable <ID>
'
```

## 4. Backend cert fingerprint

The broker pins backend's leaf certificate by SHA-256 fingerprint
to authenticate the reverse-verify channel (no CA chain, no SAN
check). When backend rotates its cert, every broker's env file
must be updated and the broker restarted.

```sh
sudo openssl x509 -in /etc/zerolink-backend/tls/cert.pem -noout \
  -fingerprint -sha256 \
  | tr -d ':' | awk -F= '{print tolower($2)}'
```

Output is 64 hex chars; that is the fingerprint.

## 5. Env file

Replace `<TOKEN>`, `<FINGERPRINT>`, `<EXTERNAL_HOST>`, `<SHORT_ID>`.

`<EXTERNAL_HOST>` is the public address clients should QUIC-connect
to (e.g. `168.107.55.126:7843` or `broker-kr.example.com:7843`).
`<SHORT_ID>` is the 2-3 char broker label (`KR`, `GZ`, ...).

```sh
sudo tee /etc/zerolink-broker/broker.env >/dev/null <<EOF
ZL_BROKER_BACKEND_URL=https://127.0.0.1:8443
ZL_BROKER_BACKEND_FINGERPRINT=<FINGERPRINT>
ZL_BROKER_SERVICE_TOKEN=<TOKEN>
ZL_BROKER_SHORT_ID=<SHORT_ID>
ZL_BROKER_LISTEN_HTTP=0.0.0.0:7842
ZL_BROKER_LISTEN_QUIC=0.0.0.0:7843
ZL_BROKER_DATAPATH_EXTERNAL_HOST=<EXTERNAL_HOST>
ZL_BROKER_DB_PATH=/var/lib/zerolink-broker/broker.db
ZL_BROKER_LOG_JSON=true
EOF

sudo chown root:zerolink /etc/zerolink-broker/broker.env
sudo chmod 640 /etc/zerolink-broker/broker.env
```

`ZL_BROKER_BACKEND_URL` uses `127.0.0.1:8443` when the broker runs
on the same host as the backend (no public network for the
reverse-verify path). For a remote backend, use its public TLS
address; the fingerprint pinning still authenticates it.

## 6. systemd unit

```sh
sudo tee /etc/systemd/system/zerolink-broker.service >/dev/null <<'EOF'
[Unit]
Description=zerolink broker (signaling + datapath)
After=network-online.target zerolink-backend.service
Wants=network-online.target

[Service]
Type=simple
User=zerolink
Group=zerolink
EnvironmentFile=/etc/zerolink-broker/broker.env
ExecStart=/usr/local/bin/zerolink-broker
Restart=on-failure
RestartSec=2

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/zerolink-broker

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
```

## 7. Firewall

The broker exposes two ports to the public internet:

- `7842/tcp` — WebSocket signaling (room create/join/destroy/list, RPC).
- `7843/udp` — QUIC datapath (TLS 1.3 + datagrams for tunnel traffic).

Both must be reachable from end-user devices. On a host with a
default-REJECT INPUT chain (Oracle Cloud Ubuntu image), insert the
ACCEPT rules before the REJECT rule:

```sh
# Find the line number of the REJECT rule
sudo iptables -L INPUT -n --line-numbers | grep REJECT
# Insert before it (replace 8 with the line number REJECT was on)
sudo iptables -I INPUT 8 -p tcp --dport 7842 -m comment \
  --comment "zerolink broker WS" -j ACCEPT
sudo iptables -I INPUT 9 -p udp --dport 7843 -m comment \
  --comment "zerolink broker QUIC" -j ACCEPT
sudo netfilter-persistent save
```

## 8. Cloud security group

Oracle Cloud, AWS, and similar all require a separate
security-group rule on top of the host firewall. For Oracle Cloud:

1. Networking -> Virtual Cloud Networks -> your VCN -> Security Lists
   -> Default Security List
2. Add Ingress Rule: Source CIDR `0.0.0.0/0`, IP Protocol TCP,
   Destination Port 7842.
3. Add Ingress Rule: Source CIDR `0.0.0.0/0`, IP Protocol UDP,
   Destination Port 7843.

Tighten the source CIDR if a known client population is acceptable.

## 9. Start

```sh
sudo systemctl enable zerolink-broker
sudo systemctl start zerolink-broker
sudo systemctl status zerolink-broker --no-pager
sudo journalctl -u zerolink-broker -n 20 --no-pager
```

The startup log emits four lines (JSON when
`ZL_BROKER_LOG_JSON=true`):

```
boot   starting zerolink-broker version=...
storage  sqlite open + migrations applied
boot   datapath listening listen=0.0.0.0:7843 external=<host>:7843 fingerprint=<64hex>
http   signaling listening addr=0.0.0.0:7842
```

The fingerprint changes on every boot (fresh self-signed cert per
process start). Clients pick it up automatically via the next WS
RPC response, so no client-side rotation runbook is needed.

## 10. Smoke test

From any host that can reach the broker:

```sh
curl -s http://<EXTERNAL_HOST>:7842/ping
curl -s http://<EXTERNAL_HOST>:7842/version
```

For the full WS + QUIC round trip, run
`broker/examples/quic_smoke.rs` against the broker (it does
create_room over WS, then bind + datagram over QUIC).

## Updates

To deploy a new broker build:

```sh
cd /opt/build/zerolink-backend
git pull
cd broker
SQLX_OFFLINE=true cargo build --release
sudo systemctl stop zerolink-broker
sudo cp target/release/zerolink-broker /usr/local/bin/
sudo systemctl start zerolink-broker
sudo journalctl -u zerolink-broker -n 20 --no-pager
```

Existing rooms in the SQLite db survive the restart; clients
reconnect when their WS goes away (B2 grace also applies on
broker restart, but only sessions whose grace window straddles
the restart benefit; a restart longer than ~30s effectively
invalidates every session).
