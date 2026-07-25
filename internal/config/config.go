// Package config manages SubReaper's runtime configuration.
package config

import "time"

// Config holds all runtime settings for SubReaper.
type Config struct {
	// Scan targets
	Target string
	List   string // path to a file containing one domain per line

	// Output
	OutputFile string
	Format     string // terminal | json | markdown | html

	// Performance
	Concurrency int
	RateLimit   int
	Timeout     time.Duration
	Retries     int

	// DNS
	ResolversFile string // path to custom resolver list
	Resolvers     []string

	// HTTP
	NoHTTP bool // skip HTTP probing (DNS-only mode)

	// Verification
	NoVerify bool // skip Stage 4 claim verification

	// Filtering
	OnlyVulnerable bool
	MinSeverity    string // info | low | medium | high | critical

	// Discovery (brute command)
	Wordlist     string
	NoCrtsh      bool
	Permutations bool

	// Discovery — OSINT sources (brute/research commands)
	Sources    []string // Explicit list of source names to use
	AllSources bool     // Use every available free passive source

	// Research options
	TechDetect   bool // Perform technology fingerprinting (Stage 2.5)
	ResearchMode bool // Passive-only mode — no active claim verification

	// Display
	NoColor bool
	Silent  bool
	Verbose bool
	JSON    bool // shorthand for --format json
}

// Default returns a Config populated with sensible defaults.
func Default() *Config {
	return &Config{
		Format:      "terminal",
		Concurrency: 50,
		RateLimit:   100,
		Timeout:     10 * time.Second,
		Retries:     2,
		MinSeverity: "info",
		Resolvers:   defaultResolvers(),
	}
}

// defaultResolvers returns a list of well-known public DNS resolvers.
func defaultResolvers() []string {
	return []string{
		"8.8.8.8:53",        // Google
		"1.1.1.1:53",        // Cloudflare
		"9.9.9.9:53",        // Quad9
		"208.67.222.222:53", // OpenDNS
	}
}
