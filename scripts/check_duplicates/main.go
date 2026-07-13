// Duplicate pattern report for patterns/ corpus.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

func main() {
	root := "patterns"
	type hit struct {
		file string
		line int
		raw  string
		key  string
	}
	var all []hit

	walk := func(subdir string) {
		dir := filepath.Join(root, subdir)
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			lines := strings.Split(string(data), "\n")
			for i, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				pat, ci := parseLine(line)
				if pat == "" {
					continue
				}
				key := pat
				if ci {
					key = "(?i)" + pat
				}
				all = append(all, hit{subdir + "/" + e.Name(), i + 1, line, key})
			}
		}
	}
	walk("secrets")
	walk("categories")

	byKey := map[string][]hit{}
	for _, h := range all {
		byKey[h.key] = append(byKey[h.key], h)
	}

	var dups []string
	for k, hs := range byKey {
		if len(hs) > 1 {
			dups = append(dups, k)
		}
	}
	sort.Strings(dups)

	fmt.Printf("Total pattern lines: %d\n", len(all))
	fmt.Printf("Unique compile keys: %d\n", len(byKey))
	fmt.Printf("Exact duplicate keys: %d\n\n", len(dups))

	if len(dups) > 0 {
		fmt.Println("=== Exact duplicates ===")
		for i, k := range dups {
			if i >= 20 {
				fmt.Printf("... and %d more\n", len(dups)-i)
				break
			}
			hs := byKey[k]
			fmt.Printf("\n[%d copies] %s\n", len(hs), trunc(k, 100))
			for _, h := range hs {
				fmt.Printf("  - %s:%d\n", h.file, h.line)
			}
		}
	}

	core := map[string]int{}
	curated := map[string]int{}
	for _, h := range all {
		if strings.HasPrefix(h.file, "secrets/core") {
			core[h.key]++
		}
		if strings.HasPrefix(h.file, "secrets/curated") {
			curated[h.key]++
		}
	}
	overlap := 0
	for k := range core {
		if curated[k] > 0 {
			overlap++
		}
	}
	fmt.Printf("\n=== core_secrets vs curated_secrets ===\n")
	fmt.Printf("core unique: %d, curated unique: %d, overlap: %d\n", len(core), len(curated), overlap)

	seen := map[string]struct{}{}
	loaded, skipped := 0, 0
	skipSet := map[string]bool{
		`\b([a-zA-Z0-9]{30})\b`:    true,
		`[a-f0-9]{40}`:             true,
		`\b(ey[a-zA-Z0-9._-]+)\b`:  true,
		`\b([a-zA-Z0-9_-]{64,})\b`: true,
		`\d+\.\d+\.\d+`:            true,
		`\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\b`: true,
		`\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`:   true,
	}
	order := []string{"secrets/core_secrets.txt", "secrets/curated_secrets.txt", "secrets/extra_secrets.txt"}
	byFile := map[string][]hit{}
	for _, h := range all {
		byFile[h.file] = append(byFile[h.file], h)
	}
	for _, f := range order {
		for _, h := range byFile[f] {
			pat, ci := parseLine(h.raw)
			if skipSet[pat] {
				continue
			}
			pat = normalize(pat)
			key := pat
			if ci && !strings.HasPrefix(key, "(?i)") {
				key = "(?i)" + key
			}
			if _, ok := seen[key]; ok {
				skipped++
				continue
			}
			if _, err := regexp.Compile(key); err != nil {
				continue
			}
			seen[key] = struct{}{}
			loaded++
		}
	}
	fmt.Printf("\n=== Runtime loader (core → curated → extra) ===\n")
	fmt.Printf("Would load: %d, skipped duplicates: %d\n", loaded, skipped)
}

func parseLine(line string) (pat string, ci bool) {
	switch {
	case strings.HasPrefix(line, "i|"):
		return strings.TrimPrefix(line, "i|"), true
	case strings.HasPrefix(line, "|"):
		return strings.TrimPrefix(line, "|"), false
	default:
		return line, false
	}
}

func normalize(pat string) string {
	repl := []struct{ old, new string }{
		{`[[:alnum:]]`, `[a-zA-Z0-9]`},
		{`[[:word:]]`, `\w`},
		{`[[:space:]]`, `\s`},
		{`\z`, `$`},
		{`\A`, `^`},
	}
	for _, r := range repl {
		pat = strings.ReplaceAll(pat, r.old, r.new)
	}
	return pat
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
