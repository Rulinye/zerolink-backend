# zerolink-backend
#
# Quick targets:
#   make            -> build for current host
#   make linux      -> cross-compile linux/amd64 (deploy target)
#   make test       -> run unit tests
#   make run        -> build and run locally with text logs
#   make clean

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.Version=$(VERSION)
BIN := zerolink-backend

.PHONY: all build linux test run lint clean

all: build

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o build/$(BIN) .

linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -trimpath -ldflags "$(LDFLAGS)" -o build/$(BIN)-linux-amd64 .

test:
	go test -race -count=1 ./...

run: build
	./build/$(BIN) -listen 127.0.0.1:8080

lint:
	go vet ./...
	gofmt -l . | tee /dev/stderr | (! grep .)

clean:
	rm -rf build
