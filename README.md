# ZSecFind

CLI scanner for **secrets and sensitive data in JavaScript, HTML, and web source files** — built for DevSecOps pipelines and local audits.

## Quick start

Patterns are embedded — clone and run:

```bash
git clone https://github.com/l4tr0d3ctism/ZSecFind.git
cd ZSecFind

go run main.go                  # scan current directory
go run main.go ./src            # scan a folder
go run main.go ./app.js         # scan one file
go run main.go https://example.com
```

Build a binary:

```bash
go build -o zsecfind .
./zsecfind ./path --only-secrets
```

## Install

```bash
go install github.com/l4tr0d3ctism/ZSecFind@latest
# or
go install github.com/l4tr0d3ctism/ZSecFind/cmd/zsecfind@latest
```

```bash
zsecfind -version
```

Cross-compile:

```bash
./build.sh      # Linux + macOS
.\build.ps1     # Windows
```

Binaries: `dist/zsecfind-linux-amd64`, `dist/zsecfind-windows-amd64.exe`

## Usage

```bash
zsecfind                          # scan .
zsecfind ./src                    # directory
zsecfind app.js config.json       # files
zsecfind -u https://example.com   # URL (+ linked .js crawl)
zsecfind -d . --only-secrets -o report.json
zsecfind -d . --only-secrets --fail-on-find   # CI gate
cat page.html | zsecfind
```

| Flag | Description |
|------|-------------|
| `-u` / `-url` | URL(s) to scan |
| `-f` / `-file` | File(s) |
| `-d` / `-dir` | Directory (recursive) |
| `-o` | Output path (`-` = stdout) |
| `-format` | `json` or `text` |
| `--only-secrets` | Only `secret` + `jwt` categories |
| `--fail-on-find` | Exit 1 if secrets/JWT found |
| `-q` | Quiet (no progress on stderr) |

## Patterns

**813+** secret regex rules plus category matchers (IP, domain, JWT, mail, …).  
Files live under `patterns/` — see `patterns/README.md`.

## What this project merges

ZSecFind is a consolidation of ideas and pattern sets commonly used for leak detection. In practice, it merges:

- **FindSomething**: the original browser-extension regex approach (web-focused patterns for JS/HTML, plus categories like domains/IPs/URLs/JWTs).
- **TruffleHog** (curated patterns): a small set of high-signal vendor token formats used as a curated layer.
- **Gitleaks** (rule coverage): rule ideas and samples used to identify missing high-value web/SaaS token formats, then ported into `patterns/` as regex lines.

This repository does not embed or run those tools directly; it embeds the resulting pattern files and runs them as a standalone Go CLI scanner.

## JSON report

```json
{
  "meta": { "tool": "zsecfind", "version": "1.0.0" },
  "summary": { "total_findings": 42, "has_sensitive": true },
  "findings": { "secret": [ ... ] },
  "files": [ ... ]
}
```

## CI example

```yaml
- run: go install github.com/l4tr0d3ctism/ZSecFind@latest
- run: zsecfind -d ./src --only-secrets --fail-on-find -o report.json
```

## Project layout

```
├── main.go
├── cmd/zsecfind/
├── internal/          # scanner, extractor, output
├── patterns/          # embedded regex rules
├── testdata/          # sample vulnerable app
└── build.sh / build.ps1
```

## Test

```bash
go test ./internal/...
zsecfind testdata/vulnerable-app --only-secrets
```
