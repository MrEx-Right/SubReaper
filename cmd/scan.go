package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

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
	domains, err := buildDomainList(cfg.Target, cfg.List)
	if err != nil {
		return err
	}
	if len(domains) == 0 {
		return fmt.Errorf("no targets specified — use --target or --list")
	}

	r, err := prepareRun()
	if err != nil {
		return err
	}

	if r.showUI {
		report.PrintBanner(os.Stderr, cfg.NoColor)
	}

	ctx, cancel := signalContext()
	defer cancel()

	bar := ui.NewScanBar(os.Stderr, len(domains), r.showUI)
	progressFn := func(scanned, total, findings int) {
		bar.Tick("", scanned, findings)
	}

	result := engine.New(cfg).Scan(ctx, domains, progressFn)
	result.Target = cfg.Target
	bar.Finish()

	if r.showUI {
		ui.PrintScanComplete(os.Stderr, cfg.NoColor, result.Stats.FindingsTotal,
			result.Duration.Round(1_000_000).String())
	}

	return r.finish(result)
}

// buildDomainList combines a single target and a list file into one slice.
func buildDomainList(target, listFile string) ([]string, error) {
	seen := make(map[string]struct{})
	var domains []string

	add := func(d string) {
		d = strings.TrimSuffix(strings.TrimSpace(strings.ToLower(d)), ".")
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
