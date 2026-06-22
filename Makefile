.PHONY: build build-linux-windows build-all extract-patterns test clean

BINARY=findsomething
VERSION=1.0.0

build: extract-patterns
	go build -ldflags "-s -w" -o $(BINARY) ./cmd/findsomething

# Linux + Windows (most common for DevSecOps)
build-linux-windows: extract-patterns
	mkdir -p dist
	GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o dist/$(BINARY)-linux-amd64 ./cmd/findsomething
	GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o dist/$(BINARY)-windows-amd64.exe ./cmd/findsomething

build-all: extract-patterns
	GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o dist/$(BINARY)-linux-amd64 ./cmd/findsomething
	GOOS=linux GOARCH=arm64 go build -ldflags "-s -w" -o dist/$(BINARY)-linux-arm64 ./cmd/findsomething
	GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w" -o dist/$(BINARY)-darwin-amd64 ./cmd/findsomething
	GOOS=darwin GOARCH=arm64 go build -ldflags "-s -w" -o dist/$(BINARY)-darwin-arm64 ./cmd/findsomething
	GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o dist/$(BINARY)-windows-amd64.exe ./cmd/findsomething

extract-patterns:
	go run ./scripts/extract_patterns

test:
	go test ./...

clean:
	rm -f $(BINARY) $(BINARY).exe
	rm -rf dist
