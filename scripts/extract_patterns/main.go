// One-time generator: reads background.js nuclei_regex and writes embedded pattern file.
package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

func main() {
	jsPath := "../../background.js"
	outPath := "../../internal/extractor/nuclei_patterns.txt"

	if len(os.Args) > 1 {
		jsPath = os.Args[1]
	}
	if len(os.Args) > 2 {
		outPath = os.Args[2]
	}

	data, err := os.ReadFile(jsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", jsPath, err)
		os.Exit(1)
	}

	lines := strings.Split(string(data), "\n")
	inBlock := false
	var patterns []string

	reLine := regexp.MustCompile(`^\s*/(.+)/([gimsuy]*)`)

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "var nuclei_regex") {
			inBlock = true
			continue
		}
		if inBlock && trimmed == "]" {
			break
		}
		if !inBlock {
			continue
		}
		m := reLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		pat := m[1]
		flags := m[2]
		caseInsensitive := strings.Contains(flags, "i")
		prefix := ""
		if caseInsensitive {
			prefix = "i|"
		} else {
			prefix = "|"
		}
		patterns = append(patterns, prefix+pat)
	}

	var out strings.Builder
	for _, p := range patterns {
		out.WriteString(p)
		out.WriteByte('\n')
	}

	if err := os.MkdirAll("../../internal/extractor", 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(outPath, []byte(out.String()), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", outPath, err)
		os.Exit(1)
	}

	// Validate compile count
	ok, fail := 0, 0
	sc := bufio.NewScanner(strings.NewReader(out.String()))
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		ci := strings.HasPrefix(line, "i|")
		pat := strings.TrimPrefix(strings.TrimPrefix(line, "i|"), "|")
		if ci {
			pat = "(?i)" + pat
		}
		if _, err := regexp.Compile(pat); err != nil {
			fail++
			fmt.Fprintf(os.Stderr, "invalid pattern: %s -> %v\n", line[:min(60, len(line))], err)
		} else {
			ok++
		}
	}
	fmt.Printf("wrote %d patterns to %s (%d compile ok, %d failed)\n", len(patterns), outPath, ok, fail)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
