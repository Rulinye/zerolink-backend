# zerolink-backend / Makefile
#
# Phase 0 baseline (build/linux/test/run/lint/clean) extended for Phase 1.
# Each binary has its own explicit target so CI cross-compile produces
# all four deliverables, not just the main one.
#
# Batch 3.3 Group 1c: gen-service-token CLI added.

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.Version=$(VERSION)

# CGO disabled because modernc.org/sqlite is pure Go. Keeps cross-compile clean.
export CGO_ENABLED=0

BIN_DIR     := bin
SERVER_BIN  := $(BIN_DIR)/zerolink-backend
ADMIN_BIN   := $(BIN_DIR)/zerolink-backend-admin-create
IMPORT_BIN  := $(BIN_DIR)/zerolink-backend-import-nodes
GENTOK_BIN  := $(BIN_DIR)/zerolink-backend-gen-service-token

.PHONY: build linux linux-amd64 linux-arm64 test run lint clean dev-db tidy \
        linux-amd64-server linux-amd64-admin linux-amd64-import linux-amd64-gentok \
        linux-arm64-server linux-arm64-admin linux-arm64-import linux-arm64-gentok

build: $(SERVER_BIN) $(ADMIN_BIN) $(IMPORT_BIN) $(GENTOK_BIN)  ## host build

$(SERVER_BIN):
	go build -ldflags "$(LDFLAGS)" -o $@ .

$(ADMIN_BIN):
	go build -ldflags "$(LDFLAGS)" -o $@ ./cmd/admin-create

$(IMPORT_BIN):
	go build -ldflags "$(LDFLAGS)" -o $@ ./cmd/import-nodes

$(GENTOK_BIN):
	go build -ldflags "$(LDFLAGS)" -o $@ ./cmd/gen-service-token

# Phase 0 alias.
linux: linux-amd64

# linux-amd64 / linux-arm64 each fan out to four independent targets so make
# evaluates them all even on a fresh checkout.
linux-amd64: linux-amd64-server linux-amd64-admin linux-amd64-import linux-amd64-gentok

linux-amd64-server:
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" \
	  -o $(BIN_DIR)/zerolink-backend-linux-amd64 .

linux-amd64-admin:
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" \
	  -o $(BIN_DIR)/zerolink-backend-admin-create-linux-amd64 ./cmd/admin-create

linux-amd64-import:
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" \
	  -o $(BIN_DIR)/zerolink-backend-import-nodes-linux-amd64 ./cmd/import-nodes

linux-amd64-gentok:
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" \
	  -o $(BIN_DIR)/zerolink-backend-gen-service-token-linux-amd64 ./cmd/gen-service-token

linux-arm64: linux-arm64-server linux-arm64-admin linux-arm64-import linux-arm64-gentok

linux-arm64-server:
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" \
	  -o $(BIN_DIR)/zerolink-backend-linux-arm64 .

linux-arm64-admin:
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" \
	  -o $(BIN_DIR)/zerolink-backend-admin-create-linux-arm64 ./cmd/admin-create

linux-arm64-import:
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" \
	  -o $(BIN_DIR)/zerolink-backend-import-nodes-linux-arm64 ./cmd/import-nodes

linux-arm64-gentok:
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" \
	  -o $(BIN_DIR)/zerolink-backend-gen-service-token-linux-arm64 ./cmd/gen-service-token

test:
	go test ./... -race -count=1

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
