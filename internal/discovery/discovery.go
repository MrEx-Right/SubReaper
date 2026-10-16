// Package discovery provides subdomain enumeration via wordlist bruteforce
// and Certificate Transparency log queries.
package discovery

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// CrtShEntry represents a single entry returned by the crt.sh JSON API.
type CrtShEntry struct {
	NameValue string `json:"name_value"`
}

// QueryCrtSh queries the Certificate Transparency log aggregator at crt.sh
// for all known subdomains of the given domain.
//
// It returns a deduplicated, cleaned list of subdomains. Wildcard entries
// (*.example.com) are normalized to their base form (example.com).
//
// crt.sh is queried by default (--no-crtsh disables it).
func QueryCrtSh(ctx context.Context, domain string) ([]string, error) {
	apiURL := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", url.QueryEscape(domain))

	// crt.sh frequently answers 502/503 under load; one retry fixes most of them.
	var entries []CrtShEntry
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		entries, err = fetchCrtSh(ctx, apiURL)
		if err == nil || ctx.Err() != nil {
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(3 * time.Second):
		}
	}
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	var subdomains []string

	for _, entry := range entries {
		// name_value may contain multiple newline-separated entries
		for _, name := range strings.Split(entry.NameValue, "\n") {
			name = strings.TrimSpace(strings.ToLower(name))

			// Normalize wildcards
			name = strings.TrimPrefix(name, "*.")

			// Basic validation: must be a subdomain of the target
			if !strings.HasSuffix(name, "."+domain) && name != domain {
				continue
			}

			// Validate it looks like a hostname
			if strings.ContainsAny(name, " \t") || name == "" {
				continue
			}

			if _, ok := seen[name]; !ok {
				seen[name] = struct{}{}
				subdomains = append(subdomains, name)
			}
		}
	}

	return subdomains, nil
}

func fetchCrtSh(ctx context.Context, apiURL string) ([]CrtShEntry, error) {
	client := &http.Client{Timeout: 60 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("crt.sh request build: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crt.sh query: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned HTTP %d", resp.StatusCode)
	}

	var entries []CrtShEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("crt.sh response decode: %w", err)
	}
	return entries, nil
}

// LoadWordlist reads a wordlist file and returns a list of candidate subdomains
// for the given domain. Each line of the file is treated as a subdomain prefix.
func LoadWordlist(path string, domain string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open wordlist: %w", err)
	}
	defer f.Close()
	return ParseWordlist(f, domain)
}

// ParseWordlist reads wordlist lines from r and returns candidate subdomains.
func ParseWordlist(r io.Reader, domain string) ([]string, error) {
	seen := make(map[string]struct{})
	var subdomains []string

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(strings.ToLower(scanner.Text()))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip trailing dots and wildcards
		line = strings.TrimPrefix(line, "*.")
		line = strings.TrimSuffix(line, ".")

		candidate := line + "." + domain
		if _, ok := seen[candidate]; !ok {
			seen[candidate] = struct{}{}
			subdomains = append(subdomains, candidate)
		}
	}

	return subdomains, scanner.Err()
}

// GeneratePermutations takes a list of known subdomains and generates likely
// permutation variants. For example, "api.example.com" might yield:
// "api-v2.example.com", "api-prod.example.com", "api-staging.example.com" etc.
func GeneratePermutations(subdomains []string, domain string) []string {
	prefixes := []string{
		"dev", "staging", "stage", "prod", "production",
		"v1", "v2", "v3", "beta", "alpha", "test", "uat",
		"internal", "admin", "api", "app", "web", "www",
		"old", "new", "legacy", "backup", "tmp",
	}

	seen := make(map[string]struct{})
	var permutations []string

	for _, sub := range subdomains {
		// Only names under the target; works for registrable domains and
		// for deeper targets such as dev.example.com alike.
		if !strings.HasSuffix(sub, "."+domain) {
			continue
		}
		label := strings.TrimSuffix(sub, "."+domain)
		if strings.Contains(label, ".") {
			// Multi-level subdomain — take just the leftmost label
			parts := strings.SplitN(label, ".", 2)
			label = parts[0]
		}

		for _, prefix := range prefixes {
			variants := []string{
				label + "-" + prefix + "." + domain,
				prefix + "-" + label + "." + domain,
				label + "." + prefix + "." + domain,
			}
			for _, v := range variants {
				if _, ok := seen[v]; !ok {
					seen[v] = struct{}{}
					permutations = append(permutations, v)
				}
			}
		}
	}

	return permutations
}

// Deduplicate returns a list of unique strings from the input.
func Deduplicate(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	result := make([]string, 0, len(items))
	for _, item := range items {
		if _, ok := seen[item]; !ok {
			seen[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}
