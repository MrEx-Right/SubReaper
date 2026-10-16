package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/MrEx-Right/SubReaper/assets"
	"github.com/MrEx-Right/SubReaper/internal/discovery"
	"github.com/MrEx-Right/SubReaper/ui"
)

// discoverOptions selects the discovery stages shared by brute and research.
type discoverOptions struct {
	crtsh        bool
	sources      []string // passive OSINT sources besides crt.sh
	wordlist     bool
	wordlistPath string // "" = built-in wordlist
	permutations bool
}

// discover gathers candidate subdomains for target. Passive sources are
// queried concurrently; failures are reported and never abort discovery.
func discover(ctx context.Context, target string, opts discoverOptions, live *ui.LiveDisplay) []string {
	var all []string

	// ── Passive sources (crt.sh + OSINT), all in parallel ───────────────────
	var names []string
	if opts.crtsh {
		names = append(names, "crtsh")
	} else if live != nil {
		live.SkipStage("crt.sh", "Certificate Transparency skipped (--no-crtsh)")
	}
	names = append(names, opts.sources...)

	if len(names) > 0 {
		var stage *ui.Stage
		if live != nil {
			stage = live.StartStage("osint", fmt.Sprintf("Querying %d passive sources in parallel…", len(names)))
		}
		results := discovery.QuerySources(ctx, target, names)
		found := 0
		for _, r := range results {
			if r.Err == nil {
				found += len(r.Subdomains)
				all = append(all, r.Subdomains...)
			}
		}
		if live != nil {
			live.DoneStage(stage, true, fmt.Sprintf("%d names from %d sources", found, len(names)))
		}
		for _, r := range results {
			reportSource(live, r)
		}
	}

	// ── Wordlist ────────────────────────────────────────────────────────────
	if opts.wordlist {
		label := opts.wordlistPath
		if label == "" {
			label = "built-in wordlist"
		}
		var (
			candidates []string
			err        error
		)
		if opts.wordlistPath == "" {
			candidates, err = discovery.ParseWordlist(bytes.NewReader(assets.DefaultWordlist), target)
		} else {
			candidates, err = discovery.LoadWordlist(opts.wordlistPath, target)
		}
		switch {
		case err != nil:
			status(live, "wordlist", false, fmt.Sprintf("Wordlist load failed: %v", err))
		default:
			status(live, "wordlist", true, fmt.Sprintf("%d candidates from %s", len(candidates), label))
			all = append(all, candidates...)
		}
	} else if live != nil {
		live.SkipStage("wordlist", "Wordlist bruteforce skipped")
	}

	// ── Permutations ────────────────────────────────────────────────────────
	if opts.permutations && len(all) > 0 {
		perms := discovery.GeneratePermutations(discovery.Deduplicate(all), target)
		status(live, "perms", true, fmt.Sprintf("%d permutations generated", len(perms)))
		all = append(all, perms...)
	} else if live != nil {
		live.SkipStage("perms", "Permutation generation skipped (use --permutations to enable)")
	}

	return discovery.Deduplicate(all)
}

// reportSource prints the outcome of one passive source.
func reportSource(live *ui.LiveDisplay, r discovery.SourceResult) {
	label := r.Source
	switch {
	case errors.Is(r.Err, discovery.ErrAPIKeyRequired):
		if live != nil {
			live.SkipStage(label, fmt.Sprintf("skipped — %v", r.Err))
		} else if !cfg.Silent {
			fmt.Fprintf(os.Stderr, "[-] skipped — %v\n", r.Err)
		}
	case r.Err != nil:
		// Source errors already carry the source name.
		status(live, label, false, fmt.Sprintf("failed — %v", r.Err))
	default:
		status(live, label, true, fmt.Sprintf("%d subdomains from %s (%s)", len(r.Subdomains), r.Source, r.Duration.Round(1_000_000)))
	}
}

// status prints a finished stage line in the live panel, or a plain line
// on stderr when the panel is off.
func status(live *ui.LiveDisplay, label string, ok bool, msg string) {
	if live != nil {
		live.DoneStage(live.StartStage(label, msg), ok, msg)
		return
	}
	if cfg.Silent {
		return
	}
	mark := "[*]"
	if !ok {
		mark = "[!]"
	}
	fmt.Fprintf(os.Stderr, "%s %s\n", mark, msg)
}

// splitSources parses a comma-separated --sources value.
func splitSources(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.ToLower(strings.TrimSpace(part))
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// validateSources rejects unknown source names before any work starts.
func validateSources(names []string) error {
	known := map[string]bool{"crtsh": true, "crt.sh": true, "otx": true}
	for _, n := range discovery.AllFreeSources {
		known[n] = true
	}
	for n := range discovery.KeyedSources {
		known[n] = true
	}
	for _, n := range names {
		if !known[n] {
			return fmt.Errorf("unknown source %q", n)
		}
	}
	return nil
}
