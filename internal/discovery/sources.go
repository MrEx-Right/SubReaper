// Package discovery — sources.go
// Provides passive subdomain enumeration from multiple OSINT sources.
//
// Sources included:
//   - crt.sh          (Certificate Transparency)
//   - Hackertarget    (api.hackertarget.com/hostsearch)
//   - URLScan.io      (urlscan.io/api/v1/search)
//   - Wayback Machine (web.archive.org CDX API)
//   - RapidDNS        (rapiddns.io/subdomain)
//   - Anubis          (anubisdb.com, formerly jldc.me)
//   - CertSpotter     (api.certspotter.com/v1/issuances)
//   - AlienVault OTX  (otx.alienvault.com — requires OTX_API_KEY)
package discovery

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const userAgent = "SubReaper/2.0 (+https://github.com/MrEx-Right/SubReaper)"

// ErrAPIKeyRequired is returned by sources that need an API key which is not set.
var ErrAPIKeyRequired = errors.New("API key required")

// AllFreeSources lists every built-in passive source that works without an
// API key, except crt.sh, which the commands control with --no-crtsh.
var AllFreeSources = []string{
	"hackertarget",
	"urlscan",
	"wayback",
	"rapiddns",
	"anubis",
	"certspotter",
}

// KeyedSources lists sources that need an API key from the environment.
// They are included in --all-sources only when their key is set.
var KeyedSources = map[string]string{
	"alienvault": "OTX_API_KEY",
}

// DefaultSources returns the free sources plus every keyed source whose key
// is present in the environment.
func DefaultSources() []string {
	out := append([]string(nil), AllFreeSources...)
	for name, env := range KeyedSources {
		if os.Getenv(env) != "" {
			out = append(out, name)
		}
	}
	return out
}

// SourceResult is the outcome of one source query.
type SourceResult struct {
	Source     string
	Subdomains []string
	Err        error
	Duration   time.Duration
}

// QuerySources queries the named sources concurrently and returns one result
// per source, in the order given. A failing source never affects the others.
func QuerySources(ctx context.Context, domain string, names []string) []SourceResult {
	results := make([]SourceResult, len(names))
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Add(1)
		go func(i int, src string) {
			defer wg.Done()
			start := time.Now()
			subs, err := QuerySource(ctx, src, domain)
			results[i] = SourceResult{Source: src, Subdomains: subs, Err: err, Duration: time.Since(start)}
		}(i, name)
	}
	wg.Wait()
	return results
}

// QuerySource dispatches a query to the named source.
func QuerySource(ctx context.Context, source, domain string) ([]string, error) {
	switch source {
	case "crtsh", "crt.sh":
		return QueryCrtSh(ctx, domain)
	case "hackertarget":
		return QueryHackertarget(ctx, domain)
	case "urlscan":
		return QueryURLScan(ctx, domain)
	case "wayback":
		return QueryWaybackMachine(ctx, domain)
	case "rapiddns":
		return QueryRapidDNS(ctx, domain)
	case "anubis":
		return QueryAnubis(ctx, domain)
	case "alienvault", "otx":
		return QueryAlienVault(ctx, domain)
	case "certspotter":
		return QueryCertSpotter(ctx, domain)
	default:
		return nil, fmt.Errorf("unknown source: %s", source)
	}
}

// ─── HTTP helper ─────────────────────────────────────────────────────────────

func newRequest(ctx context.Context, rawURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json, text/plain, text/html;q=0.9, */*;q=0.8")
	return req, nil
}

func httpGet(ctx context.Context, rawURL string, timeout time.Duration, headers map[string]string) ([]byte, error) {
	client := &http.Client{Timeout: timeout}
	req, err := newRequest(ctx, rawURL)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
}

// ─── normalise helpers ───────────────────────────────────────────────────────

// filterSubdomains removes entries that are not subdomains of the target
// domain and removes duplicates.
func filterSubdomains(domain string, items []string) []string {
	domain = strings.ToLower(domain)
	suffix := "." + domain
	seen := make(map[string]struct{})
	var out []string
	for _, s := range items {
		s = strings.ToLower(strings.TrimSpace(s))
		s = strings.TrimPrefix(s, "*.")
		s = strings.TrimSuffix(s, ".")
		if s != domain && !strings.HasSuffix(s, suffix) {
			continue
		}
		if !validHostname(s) {
			continue
		}
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

var hostnameRe = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)+$`)

func validHostname(s string) bool {
	return len(s) <= 253 && hostnameRe.MatchString(s)
}

// hostsIn extracts every hostname under domain that appears anywhere in text.
func hostsIn(domain, text string) []string {
	re := regexp.MustCompile(`(?i)(?:[a-z0-9_*](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+` + regexp.QuoteMeta(domain) + `\b`)
	return filterSubdomains(domain, re.FindAllString(text, -1))
}

// ─── Source: Hackertarget ────────────────────────────────────────────────────

// QueryHackertarget queries hackertarget.com's free host search API.
// No API key required; returns plain-text "host,ip" lines.
func QueryHackertarget(ctx context.Context, domain string) ([]string, error) {
	apiURL := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", url.QueryEscape(domain))
	body, err := httpGet(ctx, apiURL, 30*time.Second, nil)
	if err != nil {
		return nil, fmt.Errorf("hackertarget: %w", err)
	}
	text := strings.TrimSpace(string(body))
	if strings.HasPrefix(strings.ToLower(text), "error") || strings.Contains(text, "API count exceeded") {
		return nil, fmt.Errorf("hackertarget: %s", firstLine(text))
	}
	return parseHackertarget(domain, text), nil
}

func parseHackertarget(domain, text string) []string {
	var subs []string
	for _, line := range strings.Split(text, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ",", 2)
		subs = append(subs, parts[0])
	}
	return filterSubdomains(domain, subs)
}

// ─── Source: URLScan.io ──────────────────────────────────────────────────────

type urlScanResponse struct {
	Results []struct {
		Task struct {
			Domain string `json:"domain"`
		} `json:"task"`
		Page struct {
			Domain string `json:"domain"`
		} `json:"page"`
	} `json:"results"`
}

// QueryURLScan queries the urlscan.io public search API.
// Works without a key; URLSCAN_API_KEY raises the rate limit if set.
func QueryURLScan(ctx context.Context, domain string) ([]string, error) {
	apiURL := fmt.Sprintf(
		"https://urlscan.io/api/v1/search/?q=domain:%s&size=1000",
		url.QueryEscape(domain),
	)
	var headers map[string]string
	if key := os.Getenv("URLSCAN_API_KEY"); key != "" {
		headers = map[string]string{"API-Key": key}
	}
	body, err := httpGet(ctx, apiURL, 30*time.Second, headers)
	if err != nil {
		return nil, fmt.Errorf("urlscan: %w", err)
	}

	var resp urlScanResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("urlscan decode: %w", err)
	}

	var subs []string
	for _, r := range resp.Results {
		subs = append(subs, r.Task.Domain, r.Page.Domain)
	}
	return filterSubdomains(domain, subs), nil
}

// ─── Source: Wayback Machine ─────────────────────────────────────────────────

// waybackBudget bounds how long the CDX stream is read. The CDX API streams
// slowly for large domains, so results are collected as they arrive and the
// partial set is returned when the budget runs out.
var waybackBudget = 45 * time.Second

// QueryWaybackMachine queries the Internet Archive CDX API for known URLs of
// the domain and extracts unique hostnames.
func QueryWaybackMachine(ctx context.Context, domain string) ([]string, error) {
	apiURL := fmt.Sprintf(
		"https://web.archive.org/cdx/search/cdx?url=*.%s&fl=original&collapse=urlkey&output=text&limit=50000",
		url.QueryEscape(domain),
	)

	ctx, cancel := context.WithTimeout(ctx, waybackBudget)
	defer cancel()
	req, err := newRequest(ctx, apiURL)
	if err != nil {
		return nil, fmt.Errorf("wayback: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("wayback: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wayback: HTTP %d", resp.StatusCode)
	}

	subs, readErr := parseWayback(domain, io.LimitReader(resp.Body, 64*1024*1024))
	if readErr != nil && len(subs) == 0 {
		return nil, fmt.Errorf("wayback: %w", readErr)
	}
	return subs, nil // partial results on timeout are still useful
}

var waybackHostRe = regexp.MustCompile(`^(?i)(?:[a-z][a-z0-9+.-]*://)?([^/:?#\s]+)`)

func parseWayback(domain string, r io.Reader) ([]string, error) {
	var hosts []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		if m := waybackHostRe.FindStringSubmatch(strings.TrimSpace(sc.Text())); m != nil {
			hosts = append(hosts, m[1])
		}
	}
	return filterSubdomains(domain, hosts), sc.Err()
}

// ─── Source: RapidDNS ────────────────────────────────────────────────────────

// QueryRapidDNS scrapes rapiddns.io's subdomain page (HTML table).
func QueryRapidDNS(ctx context.Context, domain string) ([]string, error) {
	apiURL := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1", url.PathEscape(domain))
	body, err := httpGet(ctx, apiURL, 45*time.Second, nil)
	if err != nil {
		return nil, fmt.Errorf("rapiddns: %w", err)
	}
	return hostsIn(domain, string(body)), nil
}

// ─── Source: Anubis ──────────────────────────────────────────────────────────

// QueryAnubis queries the Anubis subdomain database (anubisdb.com).
// The old jldc.me endpoint now only redirects there.
func QueryAnubis(ctx context.Context, domain string) ([]string, error) {
	apiURL := fmt.Sprintf("https://anubisdb.com/anubis/subdomains/%s", url.PathEscape(domain))
	body, err := httpGet(ctx, apiURL, 30*time.Second, nil)
	if err != nil {
		return nil, fmt.Errorf("anubis: %w", err)
	}

	var subs []string
	if err := json.Unmarshal(body, &subs); err != nil {
		return nil, fmt.Errorf("anubis decode: %w", err)
	}
	return filterSubdomains(domain, subs), nil
}

// ─── Source: AlienVault OTX ──────────────────────────────────────────────────

type otxResponse struct {
	PassiveDNS []struct {
		Hostname string `json:"hostname"`
	} `json:"passive_dns"`
}

// QueryAlienVault queries the AlienVault OTX passive DNS API. OTX no longer
// serves this endpoint anonymously, so OTX_API_KEY must be set.
func QueryAlienVault(ctx context.Context, domain string) ([]string, error) {
	key := os.Getenv("OTX_API_KEY")
	if key == "" {
		return nil, fmt.Errorf("alienvault: %w (set OTX_API_KEY)", ErrAPIKeyRequired)
	}
	apiURL := fmt.Sprintf(
		"https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns",
		url.PathEscape(domain),
	)
	body, err := httpGet(ctx, apiURL, 45*time.Second, map[string]string{"X-OTX-API-KEY": key})
	if err != nil {
		return nil, fmt.Errorf("alienvault: %w", err)
	}

	var resp otxResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("alienvault decode: %w", err)
	}

	var subs []string
	for _, entry := range resp.PassiveDNS {
		subs = append(subs, entry.Hostname)
	}
	return filterSubdomains(domain, subs), nil
}

// ─── Source: CertSpotter ─────────────────────────────────────────────────────

type certSpotterEntry struct {
	ID       string   `json:"id"`
	DNSNames []string `json:"dns_names"`
}

// certSpotterMaxPages bounds pagination; anonymous use allows ~100 requests/hour.
const certSpotterMaxPages = 5

// QueryCertSpotter queries the CertSpotter CT log API (sslmate.com), following
// pagination. CERTSPOTTER_API_KEY raises the rate limit if set.
func QueryCertSpotter(ctx context.Context, domain string) ([]string, error) {
	var headers map[string]string
	if key := os.Getenv("CERTSPOTTER_API_KEY"); key != "" {
		headers = map[string]string{"Authorization": "Bearer " + key}
	}

	var names []string
	after := ""
	for page := 0; page < certSpotterMaxPages; page++ {
		apiURL := fmt.Sprintf(
			"https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names",
			url.QueryEscape(domain),
		)
		if after != "" {
			apiURL += "&after=" + url.QueryEscape(after)
		}
		body, err := httpGet(ctx, apiURL, 30*time.Second, headers)
		if err != nil {
			if page > 0 {
				break // keep what earlier pages returned
			}
			return nil, fmt.Errorf("certspotter: %w", err)
		}

		var entries []certSpotterEntry
		if err := json.Unmarshal(body, &entries); err != nil {
			return nil, fmt.Errorf("certspotter decode: %w", err)
		}
		for _, e := range entries {
			names = append(names, e.DNSNames...)
		}
		if len(entries) == 0 {
			break
		}
		after = entries[len(entries)-1].ID
	}
	return filterSubdomains(domain, names), nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
