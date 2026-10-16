// Package cmd implements the SubReaper CLI using cobra.
package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/MrEx-Right/SubReaper/internal/config"
	"github.com/MrEx-Right/SubReaper/internal/models"
	"github.com/MrEx-Right/SubReaper/internal/report"
	"github.com/MrEx-Right/SubReaper/internal/resolver"
	"github.com/spf13/cobra"
)

var (
	cfg     = config.Default()
	// version is overridden at build time:
	//   -ldflags "-X github.com/MrEx-Right/SubReaper/cmd.version=x.y.z"
	version = "2.0.0"
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
	report.Version = version
	rootCmd.Version = version
	rootCmd.SetVersionTemplate("subreaper v{{.Version}}\n")

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
	pf.BoolVarP(&cfg.Verbose, "verbose", "v", false, "Verbose output (lists scan errors)")

	// Performance
	pf.IntVarP(&cfg.Concurrency, "concurrency", "c", 50, "Number of concurrent workers")
	pf.IntVar(&cfg.RateLimit, "rate-limit", cfg.RateLimit, "Max DNS + HTTP requests per second (0 = unlimited)")
	pf.DurationVar(&cfg.Timeout, "timeout", cfg.Timeout, "Per-request timeout")
	pf.IntVar(&cfg.Retries, "retries", 2, "Retry count for failed requests")

	// DNS
	pf.StringVar(&cfg.ResolversFile, "resolvers", "", "File with custom DNS resolvers, one per line (ip or ip:port)")

	// Filtering
	pf.BoolVarP(&cfg.OnlyVulnerable, "only-vulnerable", "V", false, "Only show confirmed takeover candidates")
	pf.BoolVar(&cfg.OnlyVulnerable, "ov", false, "Shorthand alias for --only-vulnerable")
	pf.StringVar(&cfg.MinSeverity, "min-severity", "info", "Minimum severity: info|low|medium|high|critical")

	// HTTP
	pf.BoolVar(&cfg.NoHTTP, "no-http", false, "DNS analysis only, skip HTTP probing")
	pf.BoolVar(&cfg.NoVerify, "no-verify", false, "Skip Stage 4 claim-state verification")
}

// run holds what every command needs once its flags are validated.
type run struct {
	out      io.Writer
	close    func()
	reporter report.Reporter
	showUI   bool
}

// prepareRun validates the shared flags, loads custom resolvers and opens the
// output file. It runs before any network work so that a typo in a flag
// never costs a finished scan.
func prepareRun() (*run, error) {
	if cfg.JSON {
		cfg.Format = "json"
	}
	cfg.Format = strings.ToLower(strings.TrimSpace(cfg.Format))

	reporter, err := report.New(cfg.Format, cfg.NoColor)
	if err != nil {
		return nil, err
	}
	if tr, ok := reporter.(*report.TerminalReporter); ok {
		tr.Verbose = cfg.Verbose
	}
	if _, err := models.ParseSeverity(cfg.MinSeverity); err != nil {
		return nil, fmt.Errorf("--min-severity: %w", err)
	}

	if cfg.ResolversFile != "" {
		lines, err := loadLines(cfg.ResolversFile)
		if err != nil {
			return nil, fmt.Errorf("load resolvers: %w", err)
		}
		servers, err := resolver.NormalizeServers(lines)
		if err != nil {
			return nil, fmt.Errorf("load resolvers: %w", err)
		}
		if len(servers) == 0 {
			return nil, fmt.Errorf("load resolvers: %s contains no resolvers", cfg.ResolversFile)
		}
		cfg.Resolvers = servers
	}

	w, closeFn, err := outputWriter()
	if err != nil {
		return nil, err
	}
	return &run{
		out:      w,
		close:    closeFn,
		reporter: reporter,
		showUI:   !cfg.Silent && cfg.Format == "terminal",
	}, nil
}

// finish writes the report and reports an interrupted scan.
func (r *run) finish(result *models.ScanResult) error {
	defer r.close()
	if result.Interrupted && !cfg.Silent {
		fmt.Fprintf(os.Stderr, "[!] Scan interrupted — results cover %d domain(s) only.\n", result.Stats.DomainsScanned)
	}
	return r.reporter.Write(r.out, result)
}

// signalContext returns a context cancelled on the first Ctrl+C / SIGTERM.
// A second Ctrl+C terminates the process immediately.
func signalContext() (context.Context, context.CancelFunc) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ctx.Done()
		stop()
		if !cfg.Silent {
			fmt.Fprintln(os.Stderr, "\n[!] Interrupted — finishing up (press Ctrl+C again to quit now)...")
		}
	}()
	return ctx, stop
}

// outputWriter returns the writer to use for output (file or stdout).
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
