package extractor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractSampleHTML(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "sample.html")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}
	r := Extract(string(data), path)
	if len(r.JWT) == 0 {
		t.Error("expected jwt finding")
	}
	if len(r.Secret) == 0 {
		t.Error("expected secret finding")
	}
	foundGH := false
	for _, s := range r.Secret {
		if strings.Contains(s.Value, "ghp_") {
			foundGH = true
		}
	}
	if !foundGH {
		t.Error("expected github token pattern match")
	}
}

func TestPatternCount(t *testing.T) {
	if PatternCount() < 700 {
		t.Fatalf("expected 700+ patterns, got %d", PatternCount())
	}
}
