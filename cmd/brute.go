package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/MrEx-Right/SubReaper/internal/discovery"
	"github.com/MrEx-Right/SubReaper/internal/engine"
	"github.com/MrEx-Right/SubReaper/internal/report"
	"github.com/MrEx-Right/SubReaper/ui"
	"github.com/spf13/cobra"
)

var bruteCfg = struct {
	Wordlist     string
	NoCrtsh      bool
	Permutations bool
	Sources      string // comma-separated list of OSINT source names
	AllSources   bool   // use every available free source
	TechDetect   bool   // enable technology fingerprinting
}{}

var bruteCmd = &cobra.Command{
	Use:   "brute",
	Short: "Discover subdomains then scan for takeover vulnerabilities",
	Long: `Discover subdomains via wordlist enumeration and Certificate Transparency logs,
then scan each discovered subdomain through the full verification pipeline.

Certificate Transparency (crt.sh) queries are enabled by default.
Use --no-crtsh to disable them. The built-in wordlist is compiled into the
binary; use -w to supply your own.

Examples:
  subreaper brute -t example.com
  subreaper brute -t example.com -w custom-wordlist.txt
  subreaper brute -t example.com --permutations --no-crtsh
  subreaper brute -t example.com --only-vulnerable -f json -o results.json`,
	RunE: runBrute,
}

func init() {
	rootCmd.AddCommand(bruteCmd)
	bruteCmd.Flags().StringVarP(&cfg.Target, "target", "t", "", "Target domain (required)")
	bruteCmd.Flags().StringVarP(&bruteCfg.Wordlist, "wordlist", "w", "", "Custom wordlist file (default: built-in)")
	bruteCmd.Flags().BoolVar(&bruteCfg.NoCrtsh, "no-crtsh", false, "Skip Certificate Transparency log queries")
	bruteCmd.Flags().BoolVar(&bruteCfg.Permutations, "permutations", false, "Generate subdomain permutations from discovered names")
	_ = bruteCmd.MarkFlagRequired("target")
	bruteCmd.Flags().BoolVar(&bruteCfg.AllSources, "all-sources", false, "Query all passive OSINT sources (keyed sources only when their API key is set)")
	bruteCmd.Flags().StringVar(&bruteCfg.Sources, "sources", "", "Comma-separated OSINT sources (hackertarget,urlscan,wayback,rapiddns,anubis,certspotter,alienvault)")
	bruteCmd.Flags().BoolVar(&bruteCfg.TechDetect, "tech-detect", false, "Perform technology fingerprinting on probed subdomains")
}

func runBrute(cmd *cobra.Command, args []string) error {
	target := normalizeTarget(cfg.Target)
	if target == "" {
		return fmt.Errorf("--target is required")
	}

	var sources []string
	if bruteCfg.Sources != "" {
		sources = splitSources(bruteCfg.Sources)
	} else if bruteCfg.AllSources {
		sources = discovery.DefaultSources()
	}
	if err := validateSources(sources); err != nil {
		return err
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

	var live *ui.LiveDisplay
	if r.showUI {
		live = ui.NewLiveDisplay(os.Stderr, cfg.NoColor)
		live.Header(target)
	}

	subdomains := discover(ctx, target, discoverOptions{
		crtsh:        !bruteCfg.NoCrtsh,
		sources:      sources,
		wordlist:     true,
		wordlistPath: bruteCfg.Wordlist,
		permutations: bruteCfg.Permutations,
	}, live)

	if len(subdomains) == 0 {
		fmt.Fprintln(os.Stderr, "[!] No subdomains to scan.")
		r.close()
		return nil
	}

	if live != nil {
		live.Footer(len(subdomains))
	} else if !cfg.Silent {
		fmt.Fprintf(os.Stderr, "[*] Scanning %d unique subdomains...\n\n", len(subdomains))
	}

	scanConfig := *cfg
	scanConfig.Target = target
	scanConfig.TechDetect = bruteCfg.TechDetect

	bar := ui.NewScanBar(os.Stderr, len(subdomains), r.showUI)
	progressFn := func(scanned, total, findings int) {
		bar.Tick("", scanned, findings)
	}

	result := engine.New(&scanConfig).Scan(ctx, subdomains, progressFn)
	result.Target = target
	bar.Finish()

	if r.showUI {
		ui.PrintScanComplete(os.Stderr, cfg.NoColor, result.Stats.FindingsTotal,
			result.Duration.Round(1_000_000).String())
	}

	return r.finish(result)
}

// normalizeTarget lowercases a domain and strips whitespace and a trailing dot.
func normalizeTarget(t string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(t)), ".")
}
