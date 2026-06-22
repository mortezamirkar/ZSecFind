# Build findsomething for Linux and Windows (amd64)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "Extracting patterns..."
go run ./scripts/extract_patterns

New-Item -ItemType Directory -Force -Path dist | Out-Null

Write-Host "Building Linux amd64..."
$env:GOOS = "linux"
$env:GOARCH = "amd64"
go build -ldflags "-s -w" -o dist/findsomething-linux-amd64 ./cmd/findsomething

Write-Host "Building Windows amd64..."
$env:GOOS = "windows"
$env:GOARCH = "amd64"
go build -ldflags "-s -w" -o dist/findsomething-windows-amd64.exe ./cmd/findsomething

Remove-Item Env:GOOS -ErrorAction SilentlyContinue
Remove-Item Env:GOARCH -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Done:"
Get-ChildItem dist | Format-Table Name, @{N="Size(MB)";E={[math]::Round($_.Length/1MB,2)}}
