BINARY    := subreaper
VERSION   := 2.0.0
BUILD_DIR := build
LDFLAGS   := -ldflags="-s -w -X github.com/MrEx-Right/SubReaper/cmd.version=$(VERSION)"

.PHONY: all build clean test vet fmt install help

all: build

## build: Compile the binary for the current OS/arch
build:
	go build $(LDFLAGS) -o $(BINARY) .

## build-all: Cross-compile for Linux, Windows, and macOS
build-all:
	GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-amd64 .
	GOOS=linux   GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-arm64 .
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-windows-amd64.exe .
	GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-darwin-amd64 .
	GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-darwin-arm64 .

## test: Run all unit tests
test:
	go test ./... -v -race -timeout 30s

## vet: Run go vet
vet:
	go vet ./...

## fmt: Run gofmt
fmt:
	gofmt -w .

## clean: Remove built binaries
clean:
	rm -f $(BINARY) $(BINARY).exe
	rm -rf $(BUILD_DIR)

## install: Install to GOPATH/bin
install:
	go install $(LDFLAGS) .

## help: Show this help
help:
	@grep -E '^## ' Makefile | sed 's/## /  /'
