#!/usr/bin/env bash
# Build findsomething for Linux and Windows (amd64)
set -euo pipefail
cd "$(dirname "$0")"

echo "Extracting patterns..."
go run ./scripts/extract_patterns

mkdir -p dist

echo "Building Linux amd64..."
GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o dist/findsomething-linux-amd64 ./cmd/findsomething

echo "Building Windows amd64..."
GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o dist/findsomething-windows-amd64.exe ./cmd/findsomething

echo ""
echo "Done:"
ls -lh dist/
