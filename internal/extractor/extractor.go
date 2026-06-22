package extractor

import (
	_ "embed"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/findsomething/findsomething-cli/internal/model"
)

//go:embed nuclei_patterns.txt
var nucleiPatternsRaw string

var (
	staticExtensions = []string{".jpg", ".png", ".gif", ".css", ".svg", ".ico", ".js"}

	tldPattern = `xin|com|cn|net|com\.cn|vip|top|cc|shop|club|wang|xyz|luxe|site|news|pub|fun|online|win|red|loan|ren|mom|net\.cn|org|link|biz|bid|help|tech|date|mobi|so|me|tv|co|vc|pw|video|party|pics|website|store|ltd|ink|trade|live|wiki|space|gift|lol|work|band|info|click|photo|market|tel|social|press|game|kim|org\.cn|games|pro|men|love|studio|rocks|asia|group|science|design|software|engineer|lawyer|fit|beer|tw|io|dev|app|cloud|ai|uk|de|fr|ru|ir|我爱你|中国|公司|网络|在线|网址|网店|集团|中文网`

	nucleiRegex []*regexp.Regexp

	reSFZ            *regexp.Regexp
	reMobile         *regexp.Regexp
	reMail           *regexp.Regexp
	reIP             *regexp.Regexp
	reIPPort         *regexp.Regexp
	reDomain         *regexp.Regexp
	rePath           *regexp.Regexp
	reIncompletePath *regexp.Regexp
	reURL            *regexp.Regexp
	reJWT            *regexp.Regexp
	reAlgorithm      *regexp.Regexp
	reIPInURL        *regexp.Regexp
	reIPPortInURL    *regexp.Regexp
	reDomainInURL    *regexp.Regexp

	initOnce sync.Once
)

func initPatterns() {
	initOnce.Do(func() {
		reSFZ = regexp.MustCompile(`['"]((\d{8}(0\d|10|11|12)([0-2]\d|30|31)\d{3}$)|(\d{6}(18|19|20)\d{2}(0[1-9]|10|11|12)([0-2]\d|30|31)\d{3}(\d|X|x)))['"]`)
		reMobile = regexp.MustCompile(`['"](1(3([0-35-9]\d|4[1-8])|4[14-9]\d|5([\d]\d|7[1-79])|66\d|7[2-35-8]\d|8\d{2}|9[89]\d)\d{7})['"]`)
		reMail = regexp.MustCompile(`['"][a-zA-Z0-9._\-]*@[a-zA-Z0-9._\-]{1,63}\.[a-zA-Z]{2,}['"]`)
		reIP = regexp.MustCompile(`['"](([a-zA-Z0-9]+:)?//)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/.*?)?['"]`)
		reIPPort = regexp.MustCompile(`['"](([a-zA-Z0-9]+:)?//)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}(/.*?)?['"]`)
		reDomain = regexp.MustCompile(`['"](([a-zA-Z0-9]+:)?//)?[a-zA-Z0-9\-\.]*?\.(` + tldPattern + `)(:\d{1,5})?(/)?['"]`)
		rePath = regexp.MustCompile(`['"](?:/|\.\./|\./)[^/>< \)(\{\},'"\\]([^/>< \)(\{\},'"\\])*?['"]`)
		reIncompletePath = regexp.MustCompile(`['"][^/>< \)(\{\},'"\\][\w/]*?/[\w/]*?['"]`)
		reURL = regexp.MustCompile(`['"](([a-zA-Z0-9]+:)?//)?[a-zA-Z0-9\-\.]*?\.(` + tldPattern + `)(:\d{1,5})?(/.*?)?['"]`)
		reJWT = regexp.MustCompile(`['"](ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}|ey[A-Za-z0-9_/+-]{10,}\.[A-Za-z0-9._/+-]{10,})['"]`)
		reAlgorithm = regexp.MustCompile(`\W(Base64\.encode|Base64\.decode|btoa|atob|CryptoJS\.AES|CryptoJS\.DES|JSEncrypt|rsa|KJUR|\$\.md5|md5|sha1|sha256|sha512)[\(\.]`)
		reIPInURL = regexp.MustCompile(`['"](([a-zA-Z0-9]+:)?//)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
		reIPPortInURL = regexp.MustCompile(`['"](([a-zA-Z0-9]+:)?//)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}(/.*?)?['"]`)
		reDomainInURL = regexp.MustCompile(`['"](([a-zA-Z0-9]+:)?//)?[a-zA-Z0-9\-\.]*?\.(` + tldPattern + `)(:\d{1,5})?`)

		for _, line := range strings.Split(nucleiPatternsRaw, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			pat := line
			if strings.HasPrefix(line, "i|") {
				pat = "(?i)" + strings.TrimPrefix(line, "i|")
			} else if strings.HasPrefix(line, "|") {
				pat = strings.TrimPrefix(line, "|")
			}
			re, err := regexp.Compile(pat)
			if err != nil {
				continue
			}
			nucleiRegex = append(nucleiRegex, re)
		}
	})
}

// Extract runs all FindSomething regex rules against content.
func Extract(content, source string) *model.ScanResult {
	initPatterns()

	raw := extractRaw(content)
	result := &model.ScanResult{
		Stats: make(map[string]int),
	}

	addFindings := func(key string, values []string) {
		if len(values) == 0 {
			return
		}
		uniq := uniqueSorted(stripQuotes(values))
		findings := make([]model.Finding, 0, len(uniq))
		for _, v := range uniq {
			findings = append(findings, model.Finding{Value: v, Source: source})
		}
		switch key {
		case "ip":
			result.IP = mergeFindings(result.IP, findings)
		case "ip_port":
			result.IPPort = mergeFindings(result.IPPort, findings)
		case "domain":
			result.Domain = mergeFindings(result.Domain, findings)
		case "path":
			paths, statics := splitStatic(uniq)
			result.Path = mergeFindings(result.Path, toFindings(paths, source))
			result.Static = mergeFindings(result.Static, toFindings(statics, source))
		case "incomplete_path":
			result.IncompletePath = mergeFindings(result.IncompletePath, findings)
		case "url":
			urls, statics := splitStatic(uniq)
			result.URL = mergeFindings(result.URL, toFindings(urls, source))
			result.Static = mergeFindings(result.Static, toFindings(statics, source))
		case "sfz":
			result.SFZ = mergeFindings(result.SFZ, findings)
		case "mobile":
			result.Mobile = mergeFindings(result.Mobile, findings)
		case "mail":
			result.Mail = mergeFindings(result.Mail, findings)
		case "jwt":
			result.JWT = mergeFindings(result.JWT, findings)
		case "algorithm":
			result.Algorithm = mergeFindings(result.Algorithm, findings)
		case "secret":
			result.Secret = mergeFindings(result.Secret, findings)
		}
	}

	addFindings("sfz", raw["sfz"])
	addFindings("mobile", raw["mobile"])
	addFindings("mail", filterMail(raw["mail"]))
	addFindings("ip", raw["ip"])
	addFindings("ip_port", raw["ip_port"])
	addFindings("domain", raw["domain"])
	addFindings("path", raw["path"])
	addFindings("incomplete_path", raw["incomplete_path"])
	addFindings("url", raw["url"])
	addFindings("jwt", raw["jwt"])
	addFindings("algorithm", raw["algorithm"])
	addFindings("secret", raw["secret"])

	result.Stats = countStats(result)
	return result
}

// Merge combines two scan results (e.g. page + linked JS files).
func Merge(base, other *model.ScanResult) *model.ScanResult {
	if base == nil {
		return other
	}
	if other == nil {
		return base
	}
	base.IP = mergeFindings(base.IP, other.IP)
	base.IPPort = mergeFindings(base.IPPort, other.IPPort)
	base.Domain = mergeFindings(base.Domain, other.Domain)
	base.Path = mergeFindings(base.Path, other.Path)
	base.IncompletePath = mergeFindings(base.IncompletePath, other.IncompletePath)
	base.URL = mergeFindings(base.URL, other.URL)
	base.Static = mergeFindings(base.Static, other.Static)
	base.SFZ = mergeFindings(base.SFZ, other.SFZ)
	base.Mobile = mergeFindings(base.Mobile, other.Mobile)
	base.Mail = mergeFindings(base.Mail, other.Mail)
	base.JWT = mergeFindings(base.JWT, other.JWT)
	base.Algorithm = mergeFindings(base.Algorithm, other.Algorithm)
	base.Secret = mergeFindings(base.Secret, other.Secret)
	base.Sources = uniqueSorted(append(base.Sources, other.Sources...))
	base.Stats = countStats(base)
	return base
}

func filterMail(items []string) []string {
	badTLD := map[string]bool{"js": true, "css": true, "jpg": true, "jpeg": true, "png": true, "ico": true}
	var out []string
	for _, item := range items {
		s := strings.Trim(item, `"'`)
		at := strings.LastIndex(s, "@")
		if at < 0 {
			continue
		}
		dot := strings.LastIndex(s, ".")
		if dot <= at {
			continue
		}
		tld := strings.ToLower(s[dot+1:])
		if badTLD[tld] {
			continue
		}
		out = append(out, item)
	}
	return out
}

func extractRaw(data string) map[string][]string {
	out := map[string][]string{
		"sfz":             matchAll(reSFZ, data),
		"mobile":          matchAll(reMobile, data),
		"mail":            matchAll(reMail, data),
		"ip":              matchAll(reIP, data),
		"ip_port":         matchAll(reIPPort, data),
		"domain":          matchAll(reDomain, data),
		"path":            matchAll(rePath, data),
		"incomplete_path": matchAll(reIncompletePath, data),
		"url":             matchAll(reURL, data),
		"jwt":             matchAll(reJWT, data),
		"algorithm":       matchAll(reAlgorithm, data),
		"secret":          extractSecrets(data),
	}

	if urls := out["url"]; len(urls) > 0 {
		for _, u := range urls {
			out["ip"] = union(out["ip"], matchAll(reIPInURL, u))
			out["ip_port"] = union(out["ip_port"], matchAll(reIPPortInURL, u))
			out["domain"] = union(out["domain"], matchAll(reDomainInURL, u))
		}
	}
	return out
}

func extractSecrets(data string) []string {
	seen := make(map[string]struct{})
	var result []string
	for i := len(nucleiRegex) - 1; i >= 0; i-- {
		for _, m := range nucleiRegex[i].FindAllString(data, -1) {
			if _, ok := seen[m]; ok {
				continue
			}
			seen[m] = struct{}{}
			result = append(result, m)
		}
	}
	return result
}

func matchAll(re *regexp.Regexp, data string) []string {
	if re == nil {
		return nil
	}
	return re.FindAllString(data, -1)
}

func union(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	seen := make(map[string]struct{}, len(a)+len(b))
	for _, v := range a {
		seen[v] = struct{}{}
	}
	for _, v := range b {
		if _, ok := seen[v]; !ok {
			a = append(a, v)
			seen[v] = struct{}{}
		}
	}
	return a
}

func stripQuotes(items []string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		s := item
		if len(s) >= 2 && (s[0] == '\'' || s[0] == '"') {
			s = s[1:]
		}
		if len(s) >= 1 && (s[len(s)-1] == '\'' || s[len(s)-1] == '"') {
			s = s[:len(s)-1]
		}
		out = append(out, s)
	}
	return out
}

func splitStatic(items []string) (nonStatic, static []string) {
	for _, item := range items {
		if isStaticAsset(item) {
			static = append(static, item)
		} else {
			nonStatic = append(nonStatic, item)
		}
	}
	return
}

func isStaticAsset(item string) bool {
	for _, ext := range staticExtensions {
		if strings.Contains(item, ext) {
			if ext == ".js" && strings.Contains(item, ".jsp") {
				continue
			}
			return true
		}
	}
	return false
}

func toFindings(values []string, source string) []model.Finding {
	out := make([]model.Finding, len(values))
	for i, v := range values {
		out[i] = model.Finding{Value: v, Source: source}
	}
	return out
}

func mergeFindings(a, b []model.Finding) []model.Finding {
	seen := make(map[string]struct{})
	var out []model.Finding
	for _, f := range append(a, b...) {
		key := f.Value + "\x00" + f.Source
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Value == out[j].Value {
			return out[i].Source < out[j].Source
		}
		return out[i].Value < out[j].Value
	})
	return out
}

func uniqueSorted(items []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, item := range items {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func countStats(r *model.ScanResult) map[string]int {
	return map[string]int{
		"ip":              len(r.IP),
		"ip_port":         len(r.IPPort),
		"domain":          len(r.Domain),
		"path":            len(r.Path),
		"incomplete_path": len(r.IncompletePath),
		"url":             len(r.URL),
		"static":          len(r.Static),
		"sfz":             len(r.SFZ),
		"mobile":          len(r.Mobile),
		"mail":            len(r.Mail),
		"jwt":             len(r.JWT),
		"algorithm":       len(r.Algorithm),
		"secret":          len(r.Secret),
	}
}

// PatternCount returns loaded nuclei pattern count (for --version diagnostics).
func PatternCount() int {
	initPatterns()
	return len(nucleiRegex)
}
