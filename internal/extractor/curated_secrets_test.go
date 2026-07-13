package extractor

import (
	"strings"
	"testing"
)

func TestCuratedSecretPatterns(t *testing.T) {
	samples := map[string]string{
		"openai":      "key = \"sk-proj-abc123T3BlbkFJxyz789secretkeyhere\"",
		"anthropic":   "sk-ant-api03-" + strings.Repeat("a", 93) + "AA",
		"slack":       "xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx",
		"discord":     "https://discord.com/api/webhooks/1234567890123456789/" + strings.Repeat("a", 68),
		"huggingface": "hf_" + strings.Repeat("a", 34),
		"notion":      "secret_" + strings.Repeat("a", 43),
	}

	for name, content := range samples {
		r := Extract(content, "test")
		if len(r.Secret) == 0 {
			t.Errorf("expected secret match for %s", name)
		}
	}
}

func TestPatternCountMinimum(t *testing.T) {
	n := PatternCount()
	if n < 800 {
		t.Fatalf("expected 800+ secret patterns, got %d", n)
	}
}
