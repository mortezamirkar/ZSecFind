#!/usr/bin/env bash
# Build zsecfind for Linux and Windows (amd64)
set -euo pipefail
cd "$(dirname "$0")"

mkdir -p dist

echo "Building Linux amd64..."
GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o dist/zsecfind-linux-amd64 .

echo "Building Windows amd64..."
GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o dist/zsecfind-windows-amd64.exe .

echo ""
echo "Done:"
ls -lh dist/
