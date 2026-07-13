package crawler

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/l4tr0d3ctism/ZSecFind/internal/extractor"
	"github.com/l4tr0d3ctism/ZSecFind/internal/model"
)

// Options controls HTTP crawling behavior.
type Options struct {
	SafeMode    bool
	Timeout     time.Duration
	Concurrency int
	MaxDepth    int
	UserAgent   string
}

var (
	reHref      = regexp.MustCompile(`href=['"](.*?)['"]`)
	reSrc       = regexp.MustCompile(`src=['"](.*?)['"]`)
	reScriptSrc = regexp.MustCompile(`<script [^><]*?src=['"](.*?)['"]`)
)

// ScanURL fetches a URL, extracts findings, and optionally crawls linked assets.
func ScanURL(ctx context.Context, rawURL string, opts Options) (*model.ScanResult, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 15 * time.Second
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 8
	}
	if opts.UserAgent == "" {
		opts.UserAgent = "Jsleakfind-CLI/1.0 (DevSecOps)"
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}

	client := &http.Client{Timeout: opts.Timeout}
	body, err := fetch(ctx, client, rawURL, opts.UserAgent)
	if err != nil {
		return nil, err
	}

	result := extractor.Extract(string(body), rawURL)
	result.Target = rawURL
	result.Sources = []string{rawURL}

	links := collectLinks(string(body), parsed)
	if len(links) == 0 {
		return result, nil
	}

	var mu sync.Mutex
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup

	for _, link := range links {
		if opts.SafeMode && !isJavaScript(link) && !isScriptTag(link, string(body)) {
			continue
		}
		if link == rawURL {
			continue
		}

		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			data, err := fetch(ctx, client, u, opts.UserAgent)
			if err != nil {
				return
			}
			sub := extractor.Extract(string(data), u)
			mu.Lock()
			result = extractor.Merge(result, sub)
			result.Sources = append(result.Sources, u)
			mu.Unlock()
		}(link)
	}
	wg.Wait()
	result.Sources = unique(result.Sources)
	result.Stats = countFromResult(result)
	return result, nil
}

// ScanURLBody fetches a single URL without following links.
func ScanURLBody(ctx context.Context, rawURL string, opts Options) (*model.ScanResult, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 15 * time.Second
	}
	if opts.UserAgent == "" {
		opts.UserAgent = "Jsleakfind-CLI/1.0 (DevSecOps)"
	}
	client := &http.Client{Timeout: opts.Timeout}
	body, err := fetch(ctx, client, rawURL, opts.UserAgent)
	if err != nil {
		return nil, err
	}
	r := extractor.Extract(string(body), rawURL)
	r.Target = rawURL
	r.Sources = []string{rawURL}
	return r, nil
}

// ScanContent scans raw HTML/JS without HTTP.
func ScanContent(content, source string) *model.ScanResult {
	r := extractor.Extract(content, source)
	r.Target = source
	r.Sources = []string{source}
	return r
}

func fetch(ctx context.Context, client *http.Client, u, ua string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", ua)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", u, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("fetch %s: status %d", u, resp.StatusCode)
	}

	const maxBody = 10 << 20 // 10MB
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", u, err)
	}
	return data, nil
}

func collectLinks(source string, base *url.URL) []string {
	seen := make(map[string]struct{})
	var out []string

	add := func(raw string) {
		resolved := resolveURL(base, raw)
		if resolved == "" {
			return
		}
		if _, ok := seen[resolved]; ok {
			return
		}
		seen[resolved] = struct{}{}
		out = append(out, resolved)
	}

	for _, m := range reHref.FindAllStringSubmatch(source, -1) {
		add(m[1])
	}
	for _, m := range reSrc.FindAllStringSubmatch(source, -1) {
		add(m[1])
	}
	for _, m := range reScriptSrc.FindAllStringSubmatch(source, -1) {
		add(m[1])
	}
	return out
}

func resolveURL(base *url.URL, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "javascript:") || strings.HasPrefix(raw, "data:") || strings.HasPrefix(raw, "mailto:") {
		return ""
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return base.ResolveReference(ref).String()
}

func isJavaScript(u string) bool {
	parsed, err := url.Parse(u)
	if err != nil {
		return false
	}
	return strings.HasSuffix(strings.ToLower(parsed.Path), ".js")
}

func isScriptTag(u, source string) bool {
	return strings.Contains(source, `<script`) && strings.Contains(source, u)
}

func unique(items []string) []string {
	m := make(map[string]struct{})
	var out []string
	for _, i := range items {
		if _, ok := m[i]; ok {
			continue
		}
		m[i] = struct{}{}
		out = append(out, i)
	}
	return out
}

func countFromResult(r *model.ScanResult) map[string]int {
	return map[string]int{
		"ip": len(r.IP), "ip_port": len(r.IPPort), "domain": len(r.Domain),
		"path": len(r.Path), "incomplete_path": len(r.IncompletePath),
		"url": len(r.URL), "static": len(r.Static), "sfz": len(r.SFZ),
		"mobile": len(r.Mobile), "mail": len(r.Mail), "jwt": len(r.JWT),
		"algorithm": len(r.Algorithm), "secret": len(r.Secret),
	}
}
