package scanner

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/findsomething/findsomething-cli/internal/crawler"
	"github.com/findsomething/findsomething-cli/internal/extractor"
	"github.com/findsomething/findsomething-cli/internal/model"
)

// ScanFile reads a local file and extracts findings.
func ScanFile(path string) (*model.ScanResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	r := extractor.Extract(string(data), path)
	r.Target = path
	r.Sources = []string{path}
	return r, nil
}

// ScanDir walks a directory and scans text-like files.
func ScanDir(root string, extensions []string) ([]*model.ScanResult, error) {
	if len(extensions) == 0 {
		extensions = []string{".html", ".htm", ".js", ".jsx", ".ts", ".tsx", ".vue", ".json", ".xml", ".txt", ".env", ".yaml", ".yml", ".php", ".jsp", ".asp", ".aspx", ".cs", ".java", ".py", ".rb", ".go", ".css", ".md"}
	}
	extSet := make(map[string]bool)
	for _, e := range extensions {
		extSet[strings.ToLower(e)] = true
	}

	var results []*model.ScanResult
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			base := filepath.Base(path)
			if base == ".git" || base == "node_modules" || base == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if !extSet[ext] {
			return nil
		}
		r, err := ScanFile(path)
		if err != nil {
			return nil
		}
		if r.TotalFindings() > 0 {
			results = append(results, r)
		}
		return nil
	})
	return results, err
}

// ScanURL wraps crawler with context.
func ScanURL(ctx context.Context, u string, opts crawler.Options) (*model.ScanResult, error) {
	return crawler.ScanURL(ctx, u, opts)
}

// ScanContent scans in-memory content.
func ScanContent(content, source string) *model.ScanResult {
	return crawler.ScanContent(content, source)
}
