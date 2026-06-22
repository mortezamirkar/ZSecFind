package model

import (
	"sort"
	"time"
)

// Finding ties a value to its source location.
type Finding struct {
	Value  string `json:"value"`
	Source string `json:"source"`
}

// ScanResult is the internal per-target extraction result.
type ScanResult struct {
	Target         string
	IP             []Finding
	IPPort         []Finding
	Domain         []Finding
	Path           []Finding
	IncompletePath []Finding
	URL            []Finding
	Static         []Finding
	SFZ            []Finding
	Mobile         []Finding
	Mail           []Finding
	JWT            []Finding
	Algorithm      []Finding
	Secret         []Finding
	Sources        []string
	Stats          map[string]int
}

// HasSensitive returns true when secrets or JWT were found.
func (r *ScanResult) HasSensitive() bool {
	return len(r.Secret) > 0 || len(r.JWT) > 0
}

// TotalFindings returns the count of all extracted items.
func (r *ScanResult) TotalFindings() int {
	n := 0
	for _, s := range r.Stats {
		n += s
	}
	return n
}

// --- JSON report (organized output) ---

// Report is the top-level structured JSON output.
type Report struct {
	Meta     ReportMeta    `json:"meta"`
	Summary  ReportSummary `json:"summary"`
	Findings CategoryMap   `json:"findings"`
	Files    []FileReport  `json:"files"`
}

// ReportMeta holds scan metadata.
type ReportMeta struct {
	Tool      string `json:"tool"`
	Version   string `json:"version"`
	ScannedAt string `json:"scanned_at"`
}

// ReportSummary holds aggregate counts (only non-zero categories).
type ReportSummary struct {
	FilesScanned      int            `json:"files_scanned"`
	FilesWithFindings int            `json:"files_with_findings"`
	TotalFindings     int            `json:"total_findings"`
	HasSensitive      bool           `json:"has_sensitive"`
	ByCategory        map[string]int `json:"by_category"`
}

// CategoryMap groups all findings by type.
type CategoryMap struct {
	Secret         []FindingItem `json:"secret,omitempty"`
	JWT            []FindingItem `json:"jwt,omitempty"`
	IP             []FindingItem `json:"ip,omitempty"`
	IPPort         []FindingItem `json:"ip_port,omitempty"`
	Domain         []FindingItem `json:"domain,omitempty"`
	URL            []FindingItem `json:"url,omitempty"`
	Path           []FindingItem `json:"path,omitempty"`
	IncompletePath []FindingItem `json:"incomplete_path,omitempty"`
	Static         []FindingItem `json:"static,omitempty"`
	Mail           []FindingItem `json:"mail,omitempty"`
	Mobile         []FindingItem `json:"mobile,omitempty"`
	SFZ            []FindingItem `json:"sfz,omitempty"`
	Algorithm      []FindingItem `json:"algorithm,omitempty"`
}

// FindingItem is a single finding in the JSON report.
type FindingItem struct {
	Value string `json:"value"`
	File  string `json:"file"`
}

// FileReport is per-file breakdown.
type FileReport struct {
	Path       string            `json:"path"`
	Total      int               `json:"total"`
	Categories map[string]int    `json:"by_category"`
	Findings   map[string][]string `json:"findings,omitempty"`
}

// NewReport builds an organized report from scan results.
func NewReport(version string, results []*ScanResult) *Report {
	now := time.Now().UTC().Format(time.RFC3339)
	report := &Report{
		Meta: ReportMeta{
			Tool:      "findsomething",
			Version:   version,
			ScannedAt: now,
		},
		Summary: ReportSummary{
			ByCategory: make(map[string]int),
		},
		Findings: CategoryMap{},
		Files:    make([]FileReport, 0, len(results)),
	}

	catKeys := []struct {
		key string
		get func(*ScanResult) []Finding
		set func(*CategoryMap, []FindingItem)
	}{
		{"secret", func(r *ScanResult) []Finding { return r.Secret }, func(c *CategoryMap, items []FindingItem) { c.Secret = items }},
		{"jwt", func(r *ScanResult) []Finding { return r.JWT }, func(c *CategoryMap, items []FindingItem) { c.JWT = items }},
		{"ip", func(r *ScanResult) []Finding { return r.IP }, func(c *CategoryMap, items []FindingItem) { c.IP = items }},
		{"ip_port", func(r *ScanResult) []Finding { return r.IPPort }, func(c *CategoryMap, items []FindingItem) { c.IPPort = items }},
		{"domain", func(r *ScanResult) []Finding { return r.Domain }, func(c *CategoryMap, items []FindingItem) { c.Domain = items }},
		{"url", func(r *ScanResult) []Finding { return r.URL }, func(c *CategoryMap, items []FindingItem) { c.URL = items }},
		{"path", func(r *ScanResult) []Finding { return r.Path }, func(c *CategoryMap, items []FindingItem) { c.Path = items }},
		{"incomplete_path", func(r *ScanResult) []Finding { return r.IncompletePath }, func(c *CategoryMap, items []FindingItem) { c.IncompletePath = items }},
		{"static", func(r *ScanResult) []Finding { return r.Static }, func(c *CategoryMap, items []FindingItem) { c.Static = items }},
		{"mail", func(r *ScanResult) []Finding { return r.Mail }, func(c *CategoryMap, items []FindingItem) { c.Mail = items }},
		{"mobile", func(r *ScanResult) []Finding { return r.Mobile }, func(c *CategoryMap, items []FindingItem) { c.Mobile = items }},
		{"sfz", func(r *ScanResult) []Finding { return r.SFZ }, func(c *CategoryMap, items []FindingItem) { c.SFZ = items }},
		{"algorithm", func(r *ScanResult) []Finding { return r.Algorithm }, func(c *CategoryMap, items []FindingItem) { c.Algorithm = items }},
	}

	global := make(map[string][]FindingItem)
	for _, r := range results {
		fileReport := FileReport{
			Path:       r.Target,
			Categories: make(map[string]int),
			Findings:   make(map[string][]string),
		}
		fileTotal := 0

		for _, ck := range catKeys {
			findings := ck.get(r)
			if len(findings) == 0 {
				continue
			}
			fileTotal += len(findings)
			report.Summary.ByCategory[ck.key] += len(findings)
			fileReport.Categories[ck.key] = len(findings)

			values := make([]string, len(findings))
			for i, f := range findings {
				values[i] = f.Value
				item := FindingItem{Value: f.Value, File: f.Source}
				global[ck.key] = appendUniqueFinding(global[ck.key], item)
			}
			fileReport.Findings[ck.key] = values
		}

		fileReport.Total = fileTotal
		report.Files = append(report.Files, fileReport)

		if fileTotal > 0 {
			report.Summary.FilesWithFindings++
		}
		report.Summary.TotalFindings += fileTotal
	}

	report.Summary.FilesScanned = len(results)
	report.Summary.HasSensitive = report.Summary.ByCategory["secret"] > 0 || report.Summary.ByCategory["jwt"] > 0

	for _, ck := range catKeys {
		if items, ok := global[ck.key]; ok && len(items) > 0 {
			sort.Slice(items, func(i, j int) bool {
				if items[i].File == items[j].File {
					return items[i].Value < items[j].Value
				}
				return items[i].File < items[j].File
			})
			ck.set(&report.Findings, items)
		}
	}

	sort.Slice(report.Files, func(i, j int) bool {
		return report.Files[i].Path < report.Files[j].Path
	})

	return report
}

func appendUniqueFinding(items []FindingItem, item FindingItem) []FindingItem {
	for _, existing := range items {
		if existing.Value == item.Value && existing.File == item.File {
			return items
		}
	}
	return append(items, item)
}

// HasSensitive checks the report summary.
func (r *Report) HasSensitive() bool {
	return r.Summary.HasSensitive
}
