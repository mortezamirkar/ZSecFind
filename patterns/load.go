package patterns

import (
	"strings"
)

// TLD returns the domain TLD alternation used in domain/url patterns.
func TLD() string {
	return strings.TrimSpace(firstLine(Read("shared/tld.txt")))
}

// StaticExtensions lists file extensions treated as static assets.
func StaticExtensions() []string {
	var out []string
	for _, line := range strings.Split(Read("shared/static_extensions.txt"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// CategoryPattern loads a single-line regex from patterns/categories/<name>.txt.
func CategoryPattern(name, tld string) string {
	return expand(Read("categories/"+name+".txt"), tld)
}

// Secrets returns embedded secret pattern corpora (core, curated, extra).
func Secrets() (core, curated, extra string) {
	return Read("secrets/core_secrets.txt"),
		Read("secrets/curated_secrets.txt"),
		Read("secrets/extra_secrets.txt")
}

// Read loads a file from the embedded patterns tree.
func Read(path string) string {
	data, err := FS.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

func expand(raw, tld string) string {
	pat := firstLine(raw)
	return strings.ReplaceAll(pat, "{{TLD}}", tld)
}

func firstLine(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return line
	}
	return ""
}
