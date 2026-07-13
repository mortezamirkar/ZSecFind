package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/l4tr0d3ctism/ZSecFind/internal/extractor"
)

func main() {
	fmt.Println("=== ZSecFind Integration Verification ===")
	fmt.Println()

	n := extractor.PatternCount()
	fmt.Printf("Loaded patterns: %d\n\n", n)

	cases := []struct {
		name    string
		content string
		mustHit []string
	}{
		{"AWS AKIA", `aws_key = "AKIAIOSFODNN7EXAMPLE"`, []string{"AKIA"}},
		{"GitHub ghp", `token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890AB"`, []string{"ghp_"}},
		{"OpenAI", `sk-proj-abcd1234T3BlbkFJxyzsecretkeyabcdefghij`, []string{"T3BlbkFJ"}},
		{"Anthropic", `sk-ant-api03-` + strings.Repeat("x", 93) + `AA`, []string{"sk-ant"}},
		{"Slack xoxb", `xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx`, []string{"xoxb"}},
		{"Discord webhook", `https://discord.com/api/webhooks/1234567890123456789/` + strings.Repeat("a", 68), []string{"discord.com/api/webhooks"}},
		{"JWT", `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U`, []string{"eyJ"}},
		{"Slack webhook", `https://hooks.slack.com/services/T01/B02/xxxxxxxxxxxxxxxxxxxx`, []string{"hooks.slack.com"}},
		{"Notion", `secret_` + strings.Repeat("a", 43), []string{"secret_"}},
		{"Databricks", `dapi` + strings.Repeat("a", 32), []string{"dapi"}},
	}

	passed, failed := 0, 0
	for _, tc := range cases {
		r := extractor.Extract(tc.content, "verify")
		found := false
		var values []string
		for _, s := range r.Secret {
			values = append(values, s.Value)
			for _, sub := range tc.mustHit {
				if strings.Contains(s.Value, sub) {
					found = true
				}
			}
		}
		for _, j := range r.JWT {
			values = append(values, j.Value)
			for _, sub := range tc.mustHit {
				if strings.Contains(j.Value, sub) {
					found = true
				}
			}
		}
		if found {
			fmt.Printf("  [PASS] %s\n", tc.name)
			passed++
		} else {
			fmt.Printf("  [FAIL] %s — no match containing %v (got: %v)\n", tc.name, tc.mustHit, values)
			failed++
		}
	}

	fmt.Println()
	appPath := filepath.Join("testdata", "vulnerable-app")
	if _, err := os.Stat(appPath); err == nil {
		fmt.Println("=== vulnerable-app directory scan ===")
		// scan via reading files manually count - use subprocess
	}

	// Validate curated file compiles
	curatedPath := filepath.Join("patterns", "secrets", "curated_secrets.txt")
	data, _ := os.ReadFile(curatedPath)
	bad := 0
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pat := strings.TrimPrefix(strings.TrimPrefix(line, "i|"), "|")
		if _, err := regexp.Compile(pat); err != nil {
			if _, err2 := regexp.Compile("(?i)" + pat); err2 != nil {
				fmt.Printf("  [WARN] curated compile fail: %s — %v\n", line[:min(50, len(line))], err)
				bad++
			}
		}
	}
	fmt.Printf("\nCurated patterns with compile errors: %d\n", bad)
	fmt.Printf("\nResult: %d passed, %d failed\n", passed, failed)
	if failed > 0 || n < 780 {
		os.Exit(1)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
