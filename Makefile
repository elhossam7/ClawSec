BINARY_NAME=sentinel
VERSION?=0.1.0
BUILD_TIME=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)"

.PHONY: all build build-linux build-windows clean test test-unit test-integration test-all test-coverage lint run vet

all: clean build

build:
	go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/sentinel/

build-linux:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-amd64 ./cmd/sentinel/

build-windows:
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-windows-amd64.exe ./cmd/sentinel/

build-all: build-linux build-windows

clean:
	rm -rf bin/

# --- Testing targets ---

test: test-all

test-unit:
	go test -v -race -count=1 ./internal/...

test-integration:
	go test -v -race -count=1 -timeout 120s ./tests/...

test-all:
	go test -v -race -count=1 -timeout 120s ./...

test-coverage:
	go test -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

vet:
	go vet ./...

lint:
	golangci-lint run ./...

# --- Run targets ---

run:
	go run ./cmd/sentinel/ run

init:
	go run ./cmd/sentinel/ init

validate-config:
	go run ./cmd/sentinel/ validate-config

test-llm:
	go run ./cmd/sentinel/ test-llm

# --- Docker targets ---

docker-build:
	docker build -t sentinel:$(VERSION) -f deployments/Dockerfile .

docker-run:
	docker-compose -f deployments/docker-compose.yml up -d

install-deps:
	go mod download
	go mod tidy
