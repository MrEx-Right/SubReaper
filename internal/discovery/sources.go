// Package discovery — sources.go
// Provides passive subdomain enumeration from multiple free OSINT sources.
// All sources are queryable without API keys.
//
// Sources included:
//   - Hackertarget    (hackertarget.com/subdomains)
//   - URLScan.io      (urlscan.io/api/v1/search)
//   - Wayback Machine (web.archive.org CDX API)
//   - RapidDNS        (rapiddns.io/subdomain)
//   - Anubis/JLDC     (jldc.me/anubis/subdomains)
//   - AlienVault OTX  (otx.alienvault.com — no key needed for passive)
//   - CertSpotter     (api.certspotter.com/v1/issuances)
package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// SourceOptions configures which passive OSINT sources to query.
type SourceOptions struct {
	// Sources is an explicit whitelist of source names.
	// If empty and AllSources is false, defaults to the built-in free set.
	Sources    []string
	AllSources bool // Query every available source
}

// AllFreeSources lists every built-in passive source name.
var AllFreeSources = []string{
	"hackertarget",
	"urlscan",
	"wayback",
	"rapiddns",
	"anubis",
	"alienvault",
	"certspotter",
}

// QueryAll queries all selected passive OSINT sources concurrently and returns
// a deduplicated list of discovered subdomains. Partial failures are silently
// tolerated so that one broken source doesn't abort the entire run.
func QueryAll(ctx context.Context, domain string, opts SourceOptions) ([]string, error) {
	names := opts.Sources
	if opts.AllSources || len(names) == 0 {
		names = AllFreeSources
	}

	type result struct {
		subs []string
		src  string
		err  error
	}

	resultCh := make(chan result, len(names))
	var wg sync.WaitGroup

	for _, name := range names {
		wg.Add(1)
		go func(src string) {
			defer wg.Done()
			subs, err := QuerySource(ctx, src, domain)
			resultCh <- result{subs: subs, src: src, err: err}
		}(name)
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	seen := make(map[string]struct{})
	var all []string

	for r := range resultCh {
		if r.err != nil {
			// Non-fatal — continue with other sources
			continue
		}
		for _, s := range r.subs {
			s = strings.ToLower(strings.TrimSpace(s))
			if s == "" {
				continue
			}
			if _, ok := seen[s]; !ok {
				seen[s] = struct{}{}
				all = append(all, s)
			}
		}
	}

	return all, nil
}

// QuerySource dispatches a query to the named source.
func QuerySource(ctx context.Context, source, domain string) ([]string, error) {
	switch source {
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
	case "alienvault":
		return QueryAlienVault(ctx, domain)
	case "certspotter":
		return QueryCertSpotter(ctx, domain)
	default:
		return nil, fmt.Errorf("unknown source: %s", source)
	}
}

// ─── HTTP helper ─────────────────────────────────────────────────────────────

func httpGet(ctx context.Context, rawURL string, timeout time.Duration) ([]byte, error) {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "SubReaper/1.0 (passive-osint)")
	req.Header.Set("Accept", "application/json, text/plain, */*")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, rawURL)
	}

	return io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
}

// ─── normalise helper ─────────────────────────────────────────────────────────

// filterSubdomains removes entries that are not subdomains of the target domain.
func filterSubdomains(domain string, items []string) []string {
	suffix := "." + domain
	var out []string
	for _, s := range items {
		s = strings.ToLower(strings.TrimSpace(s))
		s = strings.TrimPrefix(s, "*.")
		s = strings.TrimSuffix(s, ".")
		if s == domain || strings.HasSuffix(s, suffix) {
			out = append(out, s)
		}
	}
	return out
}

// ─── Source: Hackertarget ────────────────────────────────────────────────────

// QueryHackertarget queries hackertarget.com's free subdomain finder API.
// No API key required; returns plain-text newline-separated results.
func QueryHackertarget(ctx context.Context, domain string) ([]string, error) {
	apiURL := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", url.QueryEscape(domain))
	body, err := httpGet(ctx, apiURL, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("hackertarget: %w", err)
	}

	// Response is: subdomain,ip — one per line
	var subs []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "error") {
			continue
		}
		parts := strings.SplitN(line, ",", 2)
		subs = append(subs, strings.TrimSpace(parts[0]))
	}
	return filterSubdomains(domain, subs), nil
}

// ─── Source: URLScan.io ───────────────────────────────────────────────────────

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
// Rate-limited but free without a key for passive queries.
func QueryURLScan(ctx context.Context, domain string) ([]string, error) {
	apiURL := fmt.Sprintf(
		"https://urlscan.io/api/v1/search/?q=domain:%s&size=10000",
		url.QueryEscape(domain),
	)
	body, err := httpGet(ctx, apiURL, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("urlscan: %w", err)
	}

	var resp urlScanResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("urlscan decode: %w", err)
	}

	seen := make(map[string]struct{})
	var subs []string
	for _, r := range resp.Results {
		for _, d := range []string{r.Task.Domain, r.Page.Domain} {
			d = strings.ToLower(strings.TrimSpace(d))
			if d == "" {
				continue
			}
			if _, ok := seen[d]; !ok {
				seen[d] = struct{}{}
				subs = append(subs, d)
			}
		}
	}
	return filterSubdomains(domain, subs), nil
}

// ─── Source: Wayback Machine ─────────────────────────────────────────────────

// QueryWaybackMachine queries the Internet Archive CDX API for all known URLs
// of the domain, then extracts unique hostnames.
func QueryWaybackMachine(ctx context.Context, domain string) ([]string, error) {
	apiURL := fmt.Sprintf(
		"https://web.archive.org/cdx/search/cdx?url=*.%s/*&output=text&fl=original&collapse=urlkey&limit=100000",
		url.QueryEscape(domain),
	)
	body, err := httpGet(ctx, apiURL, 60*time.Second)
	if err != nil {
		return nil, fmt.Errorf("wayback: %w", err)
	}

	// Extract hostnames from URLs
	re := regexp.MustCompile(`https?://([a-zA-Z0-9._-]+)`)
	matches := re.FindAllStringSubmatch(string(body), -1)

	seen := make(map[string]struct{})
	var subs []string
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		host := strings.ToLower(m[1])
		if _, ok := seen[host]; !ok {
			seen[host] = struct{}{}
			subs = append(subs, host)
		}
	}
	return filterSubdomains(domain, subs), nil
}

// ─── Source: RapidDNS ────────────────────────────────────────────────────────

// QueryRapidDNS queries rapiddns.io for subdomains.
// Free, no API key required.
func QueryRapidDNS(ctx context.Context, domain string) ([]string, error) {
	apiURL := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1&down=1", url.QueryEscape(domain))
	body, err := httpGet(ctx, apiURL, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("rapiddns: %w", err)
	}

	// Response is plain-text, one subdomain per line
	var subs []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			subs = append(subs, line)
		}
	}
	return filterSubdomains(domain, subs), nil
}

// ─── Source: Anubis / JLDC ───────────────────────────────────────────────────

// QueryAnubis queries the Anubis passive DNS API at jldc.me.
// Free, no API key required.
func QueryAnubis(ctx context.Context, domain string) ([]string, error) {
	apiURL := fmt.Sprintf("https://jldc.me/anubis/subdomains/%s", url.QueryEscape(domain))
	body, err := httpGet(ctx, apiURL, 20*time.Second)
	if err != nil {
		return nil, fmt.Errorf("anubis: %w", err)
	}

	// Response is a JSON array of strings
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

// QueryAlienVault queries the AlienVault OTX passive DNS API.
// The /indicators/domain endpoint is publicly accessible without an API key.
func QueryAlienVault(ctx context.Context, domain string) ([]string, error) {
	apiURL := fmt.Sprintf(
		"https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns",
		url.PathEscape(domain),
	)
	body, err := httpGet(ctx, apiURL, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("alienvault: %w", err)
	}

	var resp otxResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("alienvault decode: %w", err)
	}

	var subs []string
	for _, entry := range resp.PassiveDNS {
		if entry.Hostname != "" {
			subs = append(subs, entry.Hostname)
		}
	}
	return filterSubdomains(domain, subs), nil
}

// ─── Source: CertSpotter ─────────────────────────────────────────────────────

type certSpotterEntry struct {
	DNSNames []string `json:"dns_names"`
}

// QueryCertSpotter queries the CertSpotter CT log API (sslmate.com).
// 100 req/hour free, no key required for basic queries.
func QueryCertSpotter(ctx context.Context, domain string) ([]string, error) {
	apiURL := fmt.Sprintf(
		"https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names",
		url.QueryEscape(domain),
	)
	body, err := httpGet(ctx, apiURL, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("certspotter: %w", err)
	}

	var entries []certSpotterEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("certspotter decode: %w", err)
	}

	seen := make(map[string]struct{})
	var subs []string
	for _, e := range entries {
		for _, name := range e.DNSNames {
			name = strings.ToLower(strings.TrimSpace(name))
			name = strings.TrimPrefix(name, "*.")
			if _, ok := seen[name]; !ok {
				seen[name] = struct{}{}
				subs = append(subs, name)
			}
		}
	}
	return filterSubdomains(domain, subs), nil
}
