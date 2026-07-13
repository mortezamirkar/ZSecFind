package extractor

import (
	"strings"
	"testing"
)

func TestFindingLocation(t *testing.T) {
	content := "line one\nconst token = \"xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx\"\nline three"
	r := Extract(content, "test.js")
	if len(r.Secret) == 0 {
		t.Fatal("expected secret finding")
	}
	f := r.Secret[0]
	if f.StartLine != 2 {
		t.Errorf("start_line = %d, want 2", f.StartLine)
	}
	if f.StartCol <= 0 {
		t.Errorf("start_column = %d, want > 0", f.StartCol)
	}
	if f.Snippet == "" {
		t.Error("expected snippet")
	}
	if !strings.Contains(f.Snippet, "xoxb-") {
		t.Errorf("snippet = %q", f.Snippet)
	}
}

func TestSecretRuleIDFromComment(t *testing.T) {
	content := "sk-proj-abc123T3BlbkFJxyz789secretkeyhere"
	r := Extract(content, "test")
	if len(r.Secret) == 0 {
		t.Fatal("expected secret")
	}
	if r.Secret[0].RuleID == "" {
		t.Error("expected rule_id on secret finding")
	}
}
