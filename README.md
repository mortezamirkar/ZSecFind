# FindSomething

Passive information extraction tool for web source code and JavaScript — originally a browser extension, now also available as a **CLI binary** for DevSecOps pipelines.

> Original release: [Momo Security Blog](https://security.immomo.com/blog/145)

---

## CLI (DevSecOps)

Standalone Go binary that ports the extension's regex engine (**727 Nuclei/WebInfoHunter patterns**) for use in CI/CD, local scans, and automation.

### Install

**Go install (recommended)**

```bash
go install github.com/findsomething/findsomething-cli/cmd/findsomething@latest
```

Requires [Go 1.22+](https://go.dev/dl/). The binary is installed to `$GOPATH/bin` or `$HOME/go/bin` — make sure that directory is on your `PATH`.

```bash
# verify
findsomething -version
```

**Pre-built binaries**

Download from [Releases](https://github.com/findsomething/findsomething-cli/releases) (or build locally):

| Platform | File |
|----------|------|
| Linux amd64 | `findsomething-linux-amd64` |
| Windows amd64 | `findsomething-windows-amd64.exe` |

```bash
# build Linux + Windows locally
./build.sh        # Linux / macOS
.\build.ps1       # Windows PowerShell
# or
make build-linux-windows
```

Binaries are written to `dist/`.

**Build from source**

```bash
git clone https://github.com/findsomething/findsomething-cli.git
cd findsomething-cli
go build -o findsomething ./cmd/findsomething
```

---

### Usage

```bash
# Scan a URL (crawls linked .js files by default)
findsomething -u https://example.com

# Scan local files
findsomething -f app.js,config.json

# Scan a directory (skips node_modules, .git, vendor)
findsomething -d ./src

# Stdin
cat page.html | findsomething

# Secrets only + save JSON report
findsomething -d . --only-secrets -o report.json

# CI gate: exit 1 if secrets/JWT found
findsomething -d . --only-secrets --fail-on-find

# Human-readable output
findsomething -f index.html -format text
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-u`, `-url` | | Comma-separated URLs |
| `-f`, `-file` | | Comma-separated local files |
| `-d`, `-dir` | | Directory to scan recursively |
| `-o` | `-` | Output file (`-` = stdout) |
| `-format` | `json` | `json` or `text` |
| `-safe` | `true` | URL scan: only fetch `.js` resources |
| `-no-crawl` | `false` | URL scan: do not follow links |
| `-timeout` | `15` | HTTP timeout (seconds) |
| `-c` | `8` | Concurrent HTTP fetches |
| `--only-secrets` | `false` | Report only `secret` and `jwt` |
| `--only` | | Filter categories: `secret,jwt,ip,domain,...` |
| `--fail-on-find` | `false` | Exit code `1` on sensitive findings |
| `-q` | `false` | Quiet (no progress on stderr) |
| `-version` | | Print version and pattern count |

### JSON output

Results are a single structured report:

```json
{
  "meta": {
    "tool": "findsomething",
    "version": "1.0.0",
    "scanned_at": "2026-06-22T09:50:57Z"
  },
  "summary": {
    "files_scanned": 4,
    "files_with_findings": 4,
    "total_findings": 54,
    "has_sensitive": true,
    "by_category": {
      "secret": 37,
      "ip_port": 2,
      "domain": 4
    }
  },
  "findings": {
    "secret": [
      { "value": "ghp_xxx...", "file": "assets/js/config.js" }
    ]
  },
  "files": [
    {
      "path": "assets/js/config.js",
      "total": 27,
      "by_category": { "secret": 21 },
      "findings": { "secret": ["AKIA...", "ghp_..."] }
    }
  ]
}
```

### DevSecOps example

**GitLab CI**

```yaml
secret-scan:
  stage: security
  image: golang:1.22
  script:
    - go install github.com/findsomething/findsomething-cli/cmd/findsomething@latest
    - findsomething -d . --only-secrets --fail-on-find -o report.json
  artifacts:
    when: always
    paths:
      - report.json
```

**GitHub Actions**

```yaml
- name: Secret scan
  run: |
    go install github.com/findsomething/findsomething-cli/cmd/findsomething@latest
    findsomething -d . --only-secrets --fail-on-find -o report.json
```

### What it detects

| Category | Examples |
|----------|----------|
| `secret` | AWS keys, GitHub/GitLab tokens, API keys, passwords, Slack webhooks, private keys |
| `jwt` | JSON Web Tokens |
| `ip` / `ip_port` | IP addresses and host:port |
| `domain` / `url` | Domains and full URLs |
| `path` | API paths, static asset paths |
| `mail` / `mobile` | Email addresses, phone numbers |

### Test fixture

A sample vulnerable web app is included for testing:

```bash
findsomething -d testdata/vulnerable-app -o testdata/scan-result.json
go test ./...
```

---

## Browser extension

The original Chrome/Firefox extension for passive extraction while browsing.

### Chrome

1. [Chrome Web Store](https://chrome.google.com/webstore/detail/findsomething/kfhniponecokdefffkpagipffdefeldb)
2. Or load unpacked: `chrome://extensions` → Developer mode → Load unpacked → select this folder

### Firefox

1. [Firefox Add-ons](https://addons.mozilla.org/firefox/addon/findsomething/)
2. Or switch to the `firefox` branch and use **Debug Add-ons**

Extension source files: `manifest.json`, `content.js`, `background.js`, `popup.html`, etc.

---

## Project layout

```
├── cmd/findsomething/     # CLI entrypoint
├── internal/
│   ├── extractor/         # Regex engine + nuclei_patterns.txt
│   ├── crawler/           # HTTP fetch & JS crawl
│   ├── scanner/           # File/directory scanning
│   ├── model/             # Report data structures
│   └── output/            # JSON / text formatting
├── scripts/extract_patterns/  # Regenerate patterns from background.js
├── testdata/              # Sample apps for testing
├── build.sh / build.ps1   # Cross-compile Linux + Windows
└── background.js          # Original extension regex source
```

### Update patterns from extension

When `background.js` changes:

```bash
go run ./scripts/extract_patterns
go build ./cmd/findsomething
```

---

## License

See [LICENSE](LICENSE).
