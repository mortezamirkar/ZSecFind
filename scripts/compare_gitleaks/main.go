// Compare Gitleaks default rules against Jsleakfind detection.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/l4tr0d3ctism/ZSecFind/internal/extractor"
)

type glRule struct {
	id string
}

func main() {
	root := repoRoot()
	glPath := filepath.Join(root, "gitleaks-master", "config", "gitleaks.toml")
	rules := parseRules(glPath)
	samples := gitleaksSamples()

	var hit, miss []string
	for _, r := range rules {
		sample, ok := samples[r.id]
		if !ok {
			miss = append(miss, r.id+" (no test sample)")
			continue
		}
		res := extractor.Extract(sample, "compare")
		if len(res.Secret) > 0 || len(res.JWT) > 0 {
			hit = append(hit, r.id)
		} else {
			miss = append(miss, r.id)
		}
	}

	fmt.Printf("Jsleakfind patterns: %d\n", extractor.PatternCount())
	fmt.Printf("Gitleaks rules: %d\n", len(rules))
	fmt.Printf("Detected (sample test): %d\n", len(hit))
	fmt.Printf("Missed: %d\n\n", len(miss))

	fmt.Println("=== Missed Gitleaks rules ===")
	for i, id := range miss {
		if i >= 70 {
			fmt.Printf("... and %d more\n", len(miss)-i)
			break
		}
		fmt.Println(" ", id)
	}
}

func parseRules(path string) []glRule {
	data, _ := os.ReadFile(path)
	var out []glRule
	var id string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, `id = "`) {
			id = strings.Trim(strings.TrimPrefix(line, `id = "`), `"`)
			out = append(out, glRule{id: id})
		}
	}
	return out
}

func gitleaksSamples() map[string]string {
	return map[string]string{
		"1password-service-account-token": `token=ops_eyJ` + strings.Repeat("a", 260),
		"age-secret-key":                  `AGE-SECRET-KEY-1` + strings.Repeat("Q", 58),
		"anthropic-api-key":               `sk-ant-api03-` + strings.Repeat("a", 93) + `AA`,
		"alibaba-access-key-id":           `LTAIabcdefghij12345678`,
		"aws-access-token":                `AKIAIOSFODNN7EXAMPLE`,
		"atlassian-api-token":             `ATCTT3xFfG` + strings.Repeat("a", 40) + `=abc12345`,
		"artifactory-api-key":             `AKCp` + strings.Repeat("a", 69),
		"databricks-api-token":            `dapi` + strings.Repeat("a", 32),
		"discord-api-token":               `Bot MTIzNDU2Nzg5MDEyMzQ1Njc4.GaBcDe.FgHiJkLmNoPqRsTuVwXyZ1234567890`,
		"facebook-access-token":           `EAACEdEose0cBAAB7ZC9ZAZDZD`,
		"gcp-api-key":                     `AIzaSyB1234567890abcdefghijklmnopqrs`,
		"github-pat":                      `ghp_1234567890abcdefghijklmnopqrstuvwxyz1234`,
		"github-fine-grained-pat":         `github_pat_11ABCDEFG0` + strings.Repeat("a", 40),
		"gitlab-pat":                      `glpat-1234567890abcdefghij`,
		"huggingface-access-token":        `hf_` + strings.Repeat("a", 34),
		"jwt":                             `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U`,
		"mailgun-private-api-token":       `key-1234567890abcdef1234567890abcdef`,
		"notion-api-token":                `secret_` + strings.Repeat("a", 43),
		"npm-access-token":                `npm_` + strings.Repeat("a", 36),
		"openai-api-key":                  `sk-proj-abc123T3BlbkFJxyz789secretkeyhere`,
		"planetscale-api-token":           `pscale_tkn_` + strings.Repeat("a", 43),
		"postman-api-token":               `PMAK-` + strings.Repeat("a", 24) + `-` + strings.Repeat("a", 34),
		"private-key":                     `-----BEGIN RSA PRIVATE KEY-----\n` + strings.Repeat("A", 80),
		"pypi-upload-token":               `pypi-AgEIcHlwaS5vcmc` + strings.Repeat("A", 60),
		"sendgrid-api-token":              `SG.abc123.` + strings.Repeat("a", 43),
		"shopify-access-token":            `shpat_` + strings.Repeat("a", 32),
		"slack-bot-token":                 `xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx`,
		"slack-webhook-url":               `https://hooks.slack.com/services/T01/B02/xxxxxxxxxxxxxxxxxxxx`,
		"square-access-token":             `sq0atp-` + strings.Repeat("a", 22),
		"stripe-access-token":             `sk_live_1234567890abcdefghijklmn`,
		"telegram-bot-api-token":          `123456789:ABCdefGHIjklMNOpqrsTUVwxyz123456789`,
		"twilio-api-key":                  `SK1234567890abcdef1234567890abcdef`,
		"contentful-delivery-api-token":   `CFPAT-` + strings.Repeat("a", 43),
		"dropbox-api-token":               `sl.` + strings.Repeat("A", 130),
		"generic-api-key":                 `api_key = "super_secret_token_1234567890abcdef"`,
		"sidekiq-secret":                  `BUNDLE_ENTERPRISE__CONTRIBSYS__COM=cafebabe:deadbeef`,
		"curl-auth-header":                `Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.test.sig`,
		"heroku-api-key":                  `heroku_api_key = "12345678-1234-1234-1234-123456789012"`,
		"microsoft-teams-webhook":         `https://outlook.office.com/webhook/12345678-1234-1234-1234-123456789012@12345678-1234-1234-1234-123456789012/IncomingWebhook/abcdef/12345678-1234-1234-1234-123456789012`,
	}
}

func repoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
