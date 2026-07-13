# Build zsecfind for Linux and Windows (amd64)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

New-Item -ItemType Directory -Force -Path dist | Out-Null

Write-Host "Building Linux amd64..."
$env:GOOS = "linux"
$env:GOARCH = "amd64"
go build -ldflags "-s -w" -o dist/zsecfind-linux-amd64 .

Write-Host "Building Windows amd64..."
$env:GOOS = "windows"
$env:GOARCH = "amd64"
go build -ldflags "-s -w" -o dist/zsecfind-windows-amd64.exe .

Remove-Item Env:GOOS -ErrorAction SilentlyContinue
Remove-Item Env:GOARCH -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Done:"
Get-ChildItem dist | Format-Table Name, @{N="Size(MB)";E={[math]::Round($_.Length/1MB,2)}}
