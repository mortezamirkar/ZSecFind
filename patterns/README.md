# Jsleakfind patterns

All regex rules used by **Jsleakfind** are embedded from this folder at build time.

## Layout

```
patterns/
├── categories/     # One file per finding type (IP, JWT, mail, …)
├── secrets/        # Secret / API-key rule sets
└── shared/         # Shared fragments (TLD list, static extensions)
```

## `secrets/`

| File | Loaded at runtime |
|------|-------------------|
| `core_secrets.txt` | Yes — large web/JS secret rule set |
| `curated_secrets.txt` | Yes — high-signal API keys (OpenAI, Slack, AWS, …) |
| `extra_secrets.txt` | Yes — additional cloud/auth patterns |

Line format: optional `i|` (case-insensitive) or `|` prefix, then regex body.

## `categories/`

One regex per file. Domain/URL patterns may use `{{TLD}}` from `shared/tld.txt`.

`ip_port_in_url` reuses the same regex as `ip_port.txt` at runtime.
