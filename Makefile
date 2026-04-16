# zerolink-backend / Makefile
#
# Phase 0 baseline (build/linux/test/run/lint/clean) extended for Phase 1:
#   - linux-amd64 / linux-arm64 cross-compile (the Ansible role auto-picks)
#   - admin-create / import-nodes auxiliary binaries
#   - dev-db helper to bring up a scratch SQLite for `make run`

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.Version=$(VERSION)

# CGO disabled because modernc.org/sqlite is pure Go. Keeps cross-compile clean.
export CGO_ENABLED=0

BIN_DIR     := bin
SERVER_BIN  := $(BIN_DIR)/zerolink-backend
ADMIN_BIN   := $(BIN_DIR)/zerolink-backend-admin-create
IMPORT_BIN  := $(BIN_DIR)/zerolink-backend-import-nodes

ALL_BINS := $(SERVER_BIN) $(ADMIN_BIN) $(IMPORT_BIN)

.PHONY: build linux linux-amd64 linux-arm64 test run lint clean dev-db tidy

build: $(ALL_BINS)  ## host build

$(SERVER_BIN):
	go build -ldflags "$(LDFLAGS)" -o $@ .

$(ADMIN_BIN):
	go build -ldflags "$(LDFLAGS)" -o $@ ./cmd/admin-create

$(IMPORT_BIN):
	go build -ldflags "$(LDFLAGS)" -o $@ ./cmd/import-nodes

# The `linux` target stays as a Phase 0 alias (defaults to amd64).
linux: linux-amd64

linux-amd64:
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/zerolink-backend-linux-amd64 .
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/zerolink-backend-admin-create-linux-amd64 ./cmd/admin-create
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/zerolink-backend-import-nodes-linux-amd64 ./cmd/import-nodes

linux-arm64:
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/zerolink-backend-linux-arm64 .
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/zerolink-backend-admin-create-linux-arm64 ./cmd/admin-create
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/zerolink-backend-import-nodes-linux-arm64 ./cmd/import-nodes

test:
	go test ./... -race -count=1

# Local dev: ZL_JWT_SECRET is a 32-byte string; the DB lives in ./dev/.
run: build dev-db
	@ZL_JWT_SECRET="$$(head -c 32 /dev/urandom | base64 | head -c 32)" \
	 ZL_DB_PATH="./dev/zerolink.db" \
	 ZL_LISTEN="127.0.0.1:8080" \
	 ZL_LOG_JSON="false" \
	 $(SERVER_BIN)

dev-db:
	@mkdir -p ./dev

lint:
	gofmt -l . | tee /dev/stderr | (! grep .)
	go vet ./...

tidy:
	go mod tidy

clean:
	rm -rf $(BIN_DIR) ./dev
