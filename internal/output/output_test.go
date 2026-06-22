package output

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/findsomething/findsomething-cli/internal/extractor"
	"github.com/findsomething/findsomething-cli/internal/model"
)

func TestJSONReportStructure(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "vulnerable-app", "assets", "js", "config.js")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r := extractor.Extract(string(data), path)
	r.Target = path

	var buf bytes.Buffer
	SetReportVersion("1.0.0-test")
	if err := Write(&buf, []*model.ScanResult{r}, FormatJSON); err != nil {
		t.Fatal(err)
	}

	var report model.Report
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, buf.String())
	}

	if report.Meta.Tool != "findsomething" {
		t.Errorf("meta.tool = %q", report.Meta.Tool)
	}
	if report.Summary.FilesScanned != 1 {
		t.Errorf("files_scanned = %d", report.Summary.FilesScanned)
	}
	if report.Summary.ByCategory["secret"] == 0 {
		t.Error("expected secret count in summary")
	}
	if len(report.Findings.Secret) == 0 {
		t.Error("expected secret findings grouped")
	}
	if len(report.Files) != 1 || report.Files[0].Total == 0 {
		t.Error("expected per-file breakdown")
	}
}
