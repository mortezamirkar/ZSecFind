package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/findsomething/findsomething-cli/internal/model"
)

// Format is the output serialization type.
type Format string

const (
	FormatJSON Format = "json"
	FormatText Format = "text"
)

var reportVersion = "1.0.0"

// SetReportVersion sets the tool version embedded in JSON meta.
func SetReportVersion(v string) {
	reportVersion = v
}

// Write serializes scan results to w.
func Write(w io.Writer, results []*model.ScanResult, format Format) error {
	switch format {
	case FormatJSON:
		report := model.NewReport(reportVersion, results)
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	case FormatText:
		for i, r := range results {
			if i > 0 {
				fmt.Fprintln(w, "---")
			}
			writeText(w, r)
		}
		return nil
	default:
		return fmt.Errorf("unknown format: %s", format)
	}
}

func writeText(w io.Writer, r *model.ScanResult) {
	fmt.Fprintf(w, "Target: %s\n", r.Target)
	printSection(w, "SECRET", r.Secret)
	printSection(w, "JWT", r.JWT)
	printSection(w, "IP", r.IP)
	printSection(w, "IP_PORT", r.IPPort)
	printSection(w, "DOMAIN", r.Domain)
	printSection(w, "URL", r.URL)
	printSection(w, "PATH", r.Path)
	printSection(w, "INCOMPLETE_PATH", r.IncompletePath)
	printSection(w, "STATIC", r.Static)
	printSection(w, "MAIL", r.Mail)
	printSection(w, "MOBILE", r.Mobile)
	printSection(w, "ALGORITHM", r.Algorithm)
	fmt.Fprintf(w, "Total: %d findings\n", r.TotalFindings())
}

func printSection(w io.Writer, title string, items []model.Finding) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(w, "\n[%s] (%d)\n", title, len(items))
	for _, f := range items {
		if f.Source != "" {
			fmt.Fprintf(w, "  %s  (source: %s)\n", f.Value, f.Source)
		} else {
			fmt.Fprintf(w, "  %s\n", f.Value)
		}
	}
}

// WriteToFile writes results to path (stdout if path is "-" or empty).
func WriteToFile(path string, results []*model.ScanResult, format Format) error {
	if path == "" || path == "-" {
		return Write(os.Stdout, results, format)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return Write(f, results, format)
}

// FilterCategories keeps only selected categories in results.
func FilterCategories(r *model.ScanResult, categories []string) *model.ScanResult {
	if len(categories) == 0 {
		return r
	}
	keep := make(map[string]bool)
	for _, c := range categories {
		keep[strings.ToLower(strings.TrimSpace(c))] = true
	}
	out := &model.ScanResult{Target: r.Target, Sources: r.Sources, Stats: make(map[string]int)}
	if keep["ip"] {
		out.IP = r.IP
	}
	if keep["ip_port"] {
		out.IPPort = r.IPPort
	}
	if keep["domain"] {
		out.Domain = r.Domain
	}
	if keep["path"] {
		out.Path = r.Path
	}
	if keep["incomplete_path"] {
		out.IncompletePath = r.IncompletePath
	}
	if keep["url"] {
		out.URL = r.URL
	}
	if keep["static"] {
		out.Static = r.Static
	}
	if keep["sfz"] {
		out.SFZ = r.SFZ
	}
	if keep["mobile"] {
		out.Mobile = r.Mobile
	}
	if keep["mail"] {
		out.Mail = r.Mail
	}
	if keep["jwt"] {
		out.JWT = r.JWT
	}
	if keep["algorithm"] {
		out.Algorithm = r.Algorithm
	}
	if keep["secret"] {
		out.Secret = r.Secret
	}
	out.Stats = countStats(out)
	return out
}

func countStats(r *model.ScanResult) map[string]int {
	stats := make(map[string]int)
	add := func(k string, n int) {
		if n > 0 {
			stats[k] = n
		}
	}
	add("ip", len(r.IP))
	add("ip_port", len(r.IPPort))
	add("domain", len(r.Domain))
	add("path", len(r.Path))
	add("incomplete_path", len(r.IncompletePath))
	add("url", len(r.URL))
	add("static", len(r.Static))
	add("sfz", len(r.SFZ))
	add("mobile", len(r.Mobile))
	add("mail", len(r.Mail))
	add("jwt", len(r.JWT))
	add("algorithm", len(r.Algorithm))
	add("secret", len(r.Secret))
	return stats
}

// SortReportFiles sorts file reports by path for stable output.
func SortReportFiles(files []model.FileReport) {
	sort.Slice(files, func(i, j int) bool {
		return files[i].Path < files[j].Path
	})
}
