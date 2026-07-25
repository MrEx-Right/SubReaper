// Package cmd implements the SubReaper CLI using cobra.
package cmd

import (
	"fmt"
	"os"

	"github.com/MrEx-Right/SubReaper/internal/config"
	"github.com/MrEx-Right/SubReaper/internal/report"
	"github.com/spf13/cobra"
)

var (
	cfg     = config.Default()
	version = "1.0.0"
)

// rootCmd is the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "subreaper",
	Short: "Subdomain takeover scanner",
	Long: `SubReaper detects dangling subdomains and subdomain takeover vulnerabilities.

It uses a multi-stage verification pipeline — DNS chain analysis, HTTP probing,
multi-signal provider fingerprinting, and active claim verification — to produce
high-confidence findings with minimal false positives.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func init() {
	// Custom help function to print banner
	defaultHelp := rootCmd.HelpFunc()
	rootCmd.SetHelpFunc(func(c *cobra.Command, args []string) {
		if !cfg.Silent {
			report.PrintBanner(os.Stdout, cfg.NoColor)
		}
		defaultHelp(c, args)
	})

	// Global flags (available to all subcommands)
	pf := rootCmd.PersistentFlags()

	// Output
	pf.StringVarP(&cfg.OutputFile, "output", "o", "", "Write output to file (default: stdout)")
	pf.StringVarP(&cfg.Format, "format", "f", "terminal", "Output format: terminal|json|markdown|html")
	pf.BoolVarP(&cfg.JSON, "json", "j", false, "Shorthand for --format json")
	pf.BoolVar(&cfg.NoColor, "no-color", false, "Disable color output")
	pf.BoolVar(&cfg.Silent, "silent", false, "Suppress banner and progress, findings only")
	pf.BoolVarP(&cfg.Verbose, "verbose", "v", false, "Verbose output")

	// Performance
	pf.IntVarP(&cfg.Concurrency, "concurrency", "c", 50, "Number of concurrent workers")
	pf.IntVar(&cfg.RateLimit, "rate-limit", 100, "Max requests per second")
	pf.DurationVar(&cfg.Timeout, "timeout", cfg.Timeout, "Per-request timeout")
	pf.IntVar(&cfg.Retries, "retries", 2, "Retry count for failed requests")

	// DNS
	pf.StringVar(&cfg.ResolversFile, "resolvers", "", "File with custom DNS resolvers (one per line)")

	// Filtering
	pf.BoolVarP(&cfg.OnlyVulnerable, "only-vulnerable", "V", false, "Only show confirmed takeover candidates")
	pf.BoolVar(&cfg.OnlyVulnerable, "ov", false, "Shorthand alias for --only-vulnerable")
	pf.StringVar(&cfg.MinSeverity, "min-severity", "info", "Minimum severity: info|low|medium|high|critical")

	// HTTP
	pf.BoolVar(&cfg.NoHTTP, "no-http", false, "DNS analysis only, skip HTTP probing")
	pf.BoolVar(&cfg.NoVerify, "no-verify", false, "Skip Stage 4 claim-state verification")
}

// outputWriter returns the io.Writer to use for output (file or stdout).
func outputWriter() (*os.File, func(), error) {
	if cfg.OutputFile == "" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.Create(cfg.OutputFile)
	if err != nil {
		return nil, nil, fmt.Errorf("open output file: %w", err)
	}
	return f, func() { f.Close() }, nil
}

// resolvedFormat returns the effective output format after applying --json shorthand.
func resolvedFormat() string {
	if cfg.JSON {
		return "json"
	}
	return cfg.Format
}

// newReporter returns a Reporter for the current configuration.
func newReporter() (report.Reporter, error) {
	return report.New(resolvedFormat(), cfg.NoColor)
}
