package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/MrEx-Right/SubReaper/internal/engine"
	"github.com/MrEx-Right/SubReaper/internal/report"
	"github.com/MrEx-Right/SubReaper/ui"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a target domain or list of domains",
	Long: `Scan one or more domains for dangling subdomains and subdomain takeover vulnerabilities.

The scanner runs a four-stage pipeline per domain:
  1. DNS chain traversal (CNAME, NS, MX)
  2. HTTP/HTTPS probing and header analysis
  3. Multi-signal provider fingerprinting
  4. Active claim-state verification

Examples:
  subreaper scan -t example.com
  subreaper scan -t example.com --only-vulnerable --json
  subreaper scan -l domains.txt -f html -o report.html
  subreaper scan -t example.com --no-verify --min-severity high`,
	RunE: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringVarP(&cfg.Target, "target", "t", "", "Single target domain")
	scanCmd.Flags().StringVarP(&cfg.List, "list", "l", "", "File containing one domain per line")
}

func runScan(cmd *cobra.Command, args []string) error {
	// Resolve JSON shorthand
	if cfg.JSON {
		cfg.Format = "json"
	}

	showUI := !cfg.Silent && cfg.Format == "terminal"

	// Print banner unless silent or JSON
	if showUI {
		report.PrintBanner(os.Stdout, cfg.NoColor)
	}

	// Load target list
	domains, err := buildDomainList(cfg.Target, cfg.List)
	if err != nil {
		return err
	}
	if len(domains) == 0 {
		return fmt.Errorf("no targets specified — use --target or --list")
	}

	// Load custom resolvers if specified
	if cfg.ResolversFile != "" {
		resolvers, err := loadLines(cfg.ResolversFile)
		if err != nil {
			return fmt.Errorf("load resolvers: %w", err)
		}
		cfg.Resolvers = resolvers
	}

	// Setup context with clean cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		<-sigCh
		if !cfg.Silent {
			fmt.Fprintln(os.Stderr, "\n[!] Interrupted — cleaning up...")
		}
		cancel()
	}()

	// ── Animated progress bar ──────────────────────────────────────────────
	bar := ui.NewScanBar(os.Stdout, len(domains), showUI)

	progressFn := func(scanned, total, findings int) {
		// current domain isn't available at this callback level; pass empty
		bar.Tick("", scanned, findings)
	}

	// Run the engine
	e := engine.New(cfg)
	result := e.Scan(ctx, domains, progressFn)
	result.Target = cfg.Target

	bar.Finish()

	if showUI {
		ui.PrintScanComplete(os.Stdout, cfg.NoColor, result.Stats.FindingsTotal,
			result.Duration.Round(1_000_000).String())
	}

	// Write output
	w, cleanup, err := outputWriter()
	if err != nil {
		return err
	}
	defer cleanup()

	reporter, err := newReporter()
	if err != nil {
		return err
	}

	return reporter.Write(w, result)
}

// buildDomainList combines a single target and a list file into one slice.
func buildDomainList(target, listFile string) ([]string, error) {
	seen := make(map[string]struct{})
	var domains []string

	add := func(d string) {
		d = strings.TrimSpace(strings.ToLower(d))
		if d == "" || strings.HasPrefix(d, "#") {
			return
		}
		if _, ok := seen[d]; !ok {
			seen[d] = struct{}{}
			domains = append(domains, d)
		}
	}

	if target != "" {
		add(target)
	}

	if listFile != "" {
		lines, err := loadLines(listFile)
		if err != nil {
			return nil, fmt.Errorf("load list file: %w", err)
		}
		for _, line := range lines {
			add(line)
		}
	}

	return domains, nil
}

// loadLines reads a file and returns non-empty, non-comment lines.
func loadLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}
