package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/findsomething/findsomething-cli/internal/crawler"
	"github.com/findsomething/findsomething-cli/internal/extractor"
	"github.com/findsomething/findsomething-cli/internal/model"
	"github.com/findsomething/findsomething-cli/internal/output"
	"github.com/findsomething/findsomething-cli/internal/scanner"
)

var version = "1.0.0"

func main() {
	os.Exit(run())
}

func run() int {
	var (
		urls        string
		files       string
		dir         string
		outPath     string
		format      string
		safeMode    bool
		noCrawl     bool
		timeoutSec  int
		concurrency int
		failOnFind  bool
		onlySecrets bool
		categories  string
		showVersion bool
		quiet       bool
	)

	flag.StringVar(&urls, "u", "", "Comma-separated URLs to scan")
	flag.StringVar(&urls, "url", "", "Alias for -u")
	flag.StringVar(&files, "f", "", "Comma-separated local files to scan")
	flag.StringVar(&files, "file", "", "Alias for -f")
	flag.StringVar(&dir, "d", "", "Directory to scan recursively")
	flag.StringVar(&dir, "dir", "", "Alias for -d")
	flag.StringVar(&outPath, "o", "-", "Output file path (- for stdout)")
	flag.StringVar(&format, "format", "json", "Output format: json|text")
	flag.BoolVar(&safeMode, "safe", true, "Safe mode: only fetch .js linked resources (for URL scans)")
	flag.BoolVar(&noCrawl, "no-crawl", false, "Do not fetch linked resources (URL scan only)")
	flag.IntVar(&timeoutSec, "timeout", 15, "HTTP timeout in seconds")
	flag.IntVar(&concurrency, "c", 8, "Concurrent HTTP fetches")
	flag.BoolVar(&failOnFind, "fail-on-find", false, "Exit code 1 when secrets/JWT are found (CI gate)")
	flag.BoolVar(&onlySecrets, "only-secrets", false, "Only report secret and jwt categories")
	flag.StringVar(&categories, "only", "", "Comma-separated categories to include (secret,jwt,ip,...)")
	flag.BoolVar(&showVersion, "version", false, "Print version and exit")
	flag.BoolVar(&quiet, "q", false, "Suppress stderr progress")
	flag.Parse()

	if showVersion {
		fmt.Printf("findsomething %s (patterns: %d)\n", version, extractor.PatternCount())
		return 0
	}

	output.SetReportVersion(version)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var results []*model.ScanResult

	crawlOpts := crawler.Options{
		SafeMode:    safeMode,
		Timeout:     time.Duration(timeoutSec) * time.Second,
		Concurrency: concurrency,
	}

	if urls == "" && files == "" && dir == "" && flag.NArg() == 0 {
		if stat, _ := os.Stdin.Stat(); (stat.Mode() & os.ModeCharDevice) == 0 {
			data, readErr := io.ReadAll(os.Stdin)
			if readErr != nil {
				fatal(quiet, readErr)
				return 1
			}
			results = append(results, applyFilters(scanner.ScanContent(string(data), "stdin"), onlySecrets, categories))
		}
	}

	for _, u := range splitList(urls) {
		if !quiet {
			fmt.Fprintf(os.Stderr, "scanning url: %s\n", u)
		}
		r, err := scanURL(ctx, u, crawlOpts, noCrawl)
		if err != nil {
			fatal(quiet, fmt.Errorf("%s: %w", u, err))
			return 1
		}
		results = append(results, applyFilters(r, onlySecrets, categories))
	}

	for _, f := range splitList(files) {
		if !quiet {
			fmt.Fprintf(os.Stderr, "scanning file: %s\n", f)
		}
		r, err := scanner.ScanFile(f)
		if err != nil {
			fatal(quiet, fmt.Errorf("%s: %w", f, err))
			return 1
		}
		results = append(results, applyFilters(r, onlySecrets, categories))
	}

	if dir != "" {
		if !quiet {
			fmt.Fprintf(os.Stderr, "scanning directory: %s\n", dir)
		}
		dirResults, err := scanner.ScanDir(dir, nil)
		if err != nil {
			fatal(quiet, err)
			return 1
		}
		for _, r := range dirResults {
			results = append(results, applyFilters(r, onlySecrets, categories))
		}
	}

	for _, arg := range flag.Args() {
		if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
			if !quiet {
				fmt.Fprintf(os.Stderr, "scanning url: %s\n", arg)
			}
			r, err := scanURL(ctx, arg, crawlOpts, noCrawl)
			if err != nil {
				fatal(quiet, fmt.Errorf("%s: %w", arg, err))
				return 1
			}
			results = append(results, applyFilters(r, onlySecrets, categories))
		}
	}

	if len(results) == 0 {
		fmt.Fprintln(os.Stderr, "usage: findsomething -u <url> | -f <file> | -d <dir> | < stdin")
		fmt.Fprintln(os.Stderr, "       findsomething -version")
		return 2
	}

	outFmt := output.Format(strings.ToLower(format))
	if err := output.WriteToFile(outPath, results, outFmt); err != nil {
		fatal(quiet, err)
		return 1
	}

	if failOnFind {
		report := model.NewReport(version, results)
		if report.HasSensitive() {
			if !quiet {
				fmt.Fprintf(os.Stderr, "sensitive findings detected: %d secret(s), %d jwt(s)\n",
					report.Summary.ByCategory["secret"], report.Summary.ByCategory["jwt"])
			}
			return 1
		}
	}

	return 0
}

func scanURL(ctx context.Context, u string, opts crawler.Options, noCrawl bool) (*model.ScanResult, error) {
	if noCrawl {
		return crawler.ScanURLBody(ctx, u, opts)
	}
	return scanner.ScanURL(ctx, u, opts)
}

func applyFilters(r *model.ScanResult, onlySecrets bool, categories string) *model.ScanResult {
	if onlySecrets {
		return output.FilterCategories(r, []string{"secret", "jwt"})
	}
	if categories != "" {
		return output.FilterCategories(r, splitList(categories))
	}
	return r
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func fatal(quiet bool, err error) {
	if !quiet {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
	}
}
