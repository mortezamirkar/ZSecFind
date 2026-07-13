package scanner

import (
	"testing"
)

func TestScanDirParallel(t *testing.T) {
	root := "../../testdata/vulnerable-app"
	serial, err := ScanDir(root, ScanOptions{Workers: 1})
	if err != nil {
		t.Fatal(err)
	}
	parallel, err := ScanDir(root, ScanOptions{Workers: 4})
	if err != nil {
		t.Fatal(err)
	}
	if len(serial) != len(parallel) {
		t.Fatalf("worker mismatch: serial=%d parallel=%d", len(serial), len(parallel))
	}

	serialTotal := 0
	for _, r := range serial {
		serialTotal += r.TotalFindings()
	}
	parallelTotal := 0
	for _, r := range parallel {
		parallelTotal += r.TotalFindings()
	}
	if serialTotal != parallelTotal {
		t.Fatalf("findings mismatch: serial=%d parallel=%d", serialTotal, parallelTotal)
	}
}
