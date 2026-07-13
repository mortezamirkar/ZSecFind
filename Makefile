.PHONY: build build-linux-windows build-all test clean

BINARY=zsecfind
VERSION=1.0.0

build:
	go build -ldflags "-s -w" -o $(BINARY) .

build-linux-windows:
	mkdir -p dist
	GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o dist/$(BINARY)-linux-amd64 .
	GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o dist/$(BINARY)-windows-amd64.exe .

build-all:
	mkdir -p dist
	GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o dist/$(BINARY)-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build -ldflags "-s -w" -o dist/$(BINARY)-linux-arm64 .
	GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w" -o dist/$(BINARY)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build -ldflags "-s -w" -o dist/$(BINARY)-darwin-arm64 .
	GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o dist/$(BINARY)-windows-amd64.exe .

test:
	go test ./internal/... ./patterns/... ./cmd/...

clean:
	rm -f $(BINARY) $(BINARY).exe
	rm -rf dist
