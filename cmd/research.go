package cmd

import (
	"fmt"
	"os"

	"github.com/MrEx-Right/SubReaper/internal/discovery"
	"github.com/MrEx-Right/SubReaper/internal/engine"
	"github.com/MrEx-Right/SubReaper/internal/report"
	"github.com/MrEx-Right/SubReaper/ui"
	"github.com/spf13/cobra"
)

var researchCfg = struct {
	Sources    string // comma-separated OSINT source names
	AllSources bool   // use all available free sources
	TechDetect bool   // enable technology fingerprinting
	NoCrtsh    bool   // skip crt.sh
	NoWordlist bool   // skip wordlist bruteforce even if --wordlist is given
}{
	AllSources: true, // research defaults to all sources
}

var researchCmd = &cobra.Command{
	Use:   "research",
	Short: "Passive OSINT-first subdomain research and takeover analysis",
	Long: `Research performs maximum passive intelligence gathering on a target domain,
then runs the full takeover detection pipeline on every discovered subdomain.

Unlike 'brute', research is designed for stealth and depth:
  - Queries crt.sh and every passive OSINT source in parallel by default
  - Performs technology fingerprinting on every probed subdomain
  - Analyses TXT/SPF/DMARC records of the registrable domain
  - Does NOT run wordlist bruteforce by default (--wordlist to enable)
  - Skips active claim-state verification (passive mode)

Sources used by default (no API keys required):
  crt.sh, Hackertarget, URLScan.io, Wayback Machine, RapidDNS, Anubis, CertSpotter
Keyed sources, used when their key is set in the environment:
  AlienVault OTX (OTX_API_KEY)

Examples:
  subreaper research -t example.com
  subreaper research -t example.com -f html -o report.html
  subreaper research -t example.com --no-crtsh --sources hackertarget,urlscan
  subreaper research -t example.com --wordlist wordlists/custom.txt`,
	RunE: runResearch,
}

func init() {
	rootCmd.AddCommand(researchCmd)
	researchCmd.Flags().StringVarP(&cfg.Target, "target", "t", "", "Target domain (required)")
	researchCmd.Flags().BoolVar(&researchCfg.AllSources, "all-sources", true, "Query all passive OSINT sources (default: true)")
	researchCmd.Flags().StringVar(&researchCfg.Sources, "sources", "", "Comma-separated OSINT sources to use (overrides --all-sources)")
	researchCmd.Flags().BoolVar(&researchCfg.TechDetect, "tech-detect", true, "Perform technology fingerprinting (default: true)")
	researchCmd.Flags().BoolVar(&researchCfg.NoCrtsh, "no-crtsh", false, "Skip Certificate Transparency queries")
	researchCmd.Flags().BoolVar(&researchCfg.NoWordlist, "no-wordlist", false, "Skip wordlist bruteforce even when --wordlist is given")
	researchCmd.Flags().StringVarP(&cfg.Wordlist, "wordlist", "w", "", "Enable wordlist bruteforce with this file")
	_ = researchCmd.MarkFlagRequired("target")
}

func runResearch(cmd *cobra.Command, args []string) error {
	target := normalizeTarget(cfg.Target)
	if target == "" {
		return fmt.Errorf("--target is required")
	}

	var sources []string
	if researchCfg.Sources != "" {
		sources = splitSources(researchCfg.Sources)
	} else if researchCfg.AllSources {
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
		crtsh:        !researchCfg.NoCrtsh,
		sources:      sources,
		wordlist:     cfg.Wordlist != "" && !researchCfg.NoWordlist,
		wordlistPath: cfg.Wordlist,
	}, live)

	if len(subdomains) == 0 {
		fmt.Fprintln(os.Stderr, "[!] No subdomains discovered — nothing to scan.")
		r.close()
		return nil
	}

	if live != nil {
		live.Footer(len(subdomains))
	} else if !cfg.Silent {
		fmt.Fprintf(os.Stderr, "[*] Scanning %d unique subdomains (passive mode)...\n\n", len(subdomains))
	}

	// Research mode: passive, tech-detect on, no active claim verification.
	scanConfig := *cfg
	scanConfig.Target = target
	scanConfig.NoVerify = true
	scanConfig.ResearchMode = true
	scanConfig.TechDetect = researchCfg.TechDetect

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
