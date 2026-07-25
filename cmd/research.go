package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/MrEx-Right/SubReaper/internal/config"
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
	NoWordlist bool   // skip wordlist bruteforce
}{
	AllSources: true, // research defaults to all sources
}

var researchCmd = &cobra.Command{
	Use:   "research",
	Short: "Passive OSINT-first subdomain research and takeover analysis",
	Long: `Research performs maximum passive intelligence gathering on a target domain,
then runs the full takeover detection pipeline on every discovered subdomain.

Unlike 'brute', research is designed for stealth and depth:
  - Queries all 8 free passive OSINT sources by default (crt.sh + 7 more)
  - Performs technology fingerprinting on every live subdomain
  - Analyses TXT/SPF/DMARC records for email takeover vectors
  - Does NOT run wordlist bruteforce by default (--wordlist to enable)
  - Skips active claim-state verification (passive mode)

Sources used by default (no API keys required):
  crt.sh, Hackertarget, URLScan.io, Wayback Machine, RapidDNS,
  Anubis/JLDC, AlienVault OTX, CertSpotter

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
	researchCmd.Flags().BoolVar(&researchCfg.AllSources, "all-sources", true, "Query all free passive OSINT sources (default: true)")
	researchCmd.Flags().StringVar(&researchCfg.Sources, "sources", "", "Comma-separated OSINT sources to use (overrides --all-sources)")
	researchCmd.Flags().BoolVar(&researchCfg.TechDetect, "tech-detect", true, "Perform technology fingerprinting (default: true)")
	researchCmd.Flags().BoolVar(&researchCfg.NoCrtsh, "no-crtsh", false, "Skip Certificate Transparency queries")
	researchCmd.Flags().BoolVar(&researchCfg.NoWordlist, "no-wordlist", true, "Skip wordlist bruteforce (default: true)")
	researchCmd.Flags().StringVarP(&cfg.Wordlist, "wordlist", "w", "", "Enable wordlist bruteforce with this file")
	_ = researchCmd.MarkFlagRequired("target")
}

func runResearch(cmd *cobra.Command, args []string) error {
	if cfg.JSON {
		cfg.Format = "json"
	}

	showUI := !cfg.Silent && cfg.Format == "terminal"

	if showUI {
		report.PrintBanner(os.Stderr, cfg.NoColor)
	}

	target := cfg.Target
	if target == "" {
		return fmt.Errorf("--target is required")
	}

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

	// ── Live display panel ───────────────────────────────────────────────────
	var live *ui.LiveDisplay
	if showUI {
		live = ui.NewLiveDisplay(os.Stderr, cfg.NoColor)
		live.Header(target)
	}

	var allSubdomains []string

	// ── Stage 1: crt.sh Certificate Transparency ─────────────────────────────
	if !researchCfg.NoCrtsh {
		if showUI {
			stage := live.StartStage("crt.sh", fmt.Sprintf("Certificate Transparency logs for %s…", target))
			ctSubs, err := discovery.QueryCrtSh(ctx, target)
			if err != nil {
				live.DoneStage(stage, false, fmt.Sprintf("crt.sh failed: %v", err))
			} else {
				live.DoneStage(stage, true, fmt.Sprintf("%d subdomains via CT logs", len(ctSubs)))
				allSubdomains = append(allSubdomains, ctSubs...)
			}
		} else {
			ctSubs, err := discovery.QueryCrtSh(ctx, target)
			if err == nil {
				if !cfg.Silent {
					fmt.Fprintf(os.Stderr, "[*] crt.sh: %d subdomains\n", len(ctSubs))
				}
				allSubdomains = append(allSubdomains, ctSubs...)
			}
		}
	} else if showUI {
		live.SkipStage("crt.sh", "Certificate Transparency skipped")
	}

	// ── Stage 1.5: Multi-source OSINT (all 7 free sources) ───────────────────
	var osintSources []string
	if researchCfg.Sources != "" {
		for _, s := range strings.Split(researchCfg.Sources, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				osintSources = append(osintSources, s)
			}
		}
	} else if researchCfg.AllSources {
		osintSources = discovery.AllFreeSources
	}

	for _, src := range osintSources {
		if showUI {
			stage := live.StartStage(src, fmt.Sprintf("Querying %s…", src))
			subs, err := discovery.QuerySource(ctx, src, target)
			if err != nil {
				live.DoneStage(stage, false, fmt.Sprintf("%s failed: %v", src, err))
			} else {
				live.DoneStage(stage, true, fmt.Sprintf("%d subdomains from %s", len(subs), src))
				allSubdomains = append(allSubdomains, subs...)
			}
		} else {
			subs, err := discovery.QuerySource(ctx, src, target)
			if err == nil {
				if !cfg.Silent {
					fmt.Fprintf(os.Stderr, "[*] %s: %d subdomains\n", src, len(subs))
				}
				allSubdomains = append(allSubdomains, subs...)
			}
		}
	}

	// ── Stage 2: Wordlist (opt-in only) ──────────────────────────────────────
	if cfg.Wordlist != "" {
		if showUI {
			stage := live.StartStage("wordlist", fmt.Sprintf("Loading %s…", cfg.Wordlist))
			wlSubs, err := discovery.LoadWordlist(cfg.Wordlist, target)
			if err != nil {
				live.DoneStage(stage, false, fmt.Sprintf("Wordlist load failed: %v", err))
			} else {
				live.DoneStage(stage, true, fmt.Sprintf("%d candidates from wordlist", len(wlSubs)))
				allSubdomains = append(allSubdomains, wlSubs...)
			}
		} else {
			wlSubs, err := discovery.LoadWordlist(cfg.Wordlist, target)
			if err == nil {
				if !cfg.Silent {
					fmt.Fprintf(os.Stderr, "[*] Wordlist: %d candidates\n", len(wlSubs))
				}
				allSubdomains = append(allSubdomains, wlSubs...)
			}
		}
	} else if showUI {
		live.SkipStage("wordlist", "Wordlist bruteforce skipped (use --wordlist <file> to enable)")
	}

	// ── Deduplicate ──────────────────────────────────────────────────────────
	allSubdomains = discovery.Deduplicate(allSubdomains)

	if len(allSubdomains) == 0 {
		fmt.Fprintln(os.Stderr, "[!] No subdomains discovered — nothing to scan.")
		return nil
	}

	// ── Scanning footer ───────────────────────────────────────────────────────
	if showUI {
		live.Footer(len(allSubdomains))
	} else if !cfg.Silent {
		fmt.Fprintf(os.Stderr, "[*] Scanning %d unique subdomains (passive mode)...\n\n", len(allSubdomains))
	}

	// ── Scan config — research mode: passive, tech-detect ON, no active verify ─
	scanConfig := &config.Config{
		Target:         target,
		Format:         cfg.Format,
		OutputFile:     cfg.OutputFile,
		Concurrency:    cfg.Concurrency,
		RateLimit:      cfg.RateLimit,
		Timeout:        cfg.Timeout,
		Retries:        cfg.Retries,
		Resolvers:      cfg.Resolvers,
		NoHTTP:         cfg.NoHTTP,
		NoVerify:       true, // research = passive; no active claim checks
		ResearchMode:   true, // suppress active verification stage
		OnlyVulnerable: cfg.OnlyVulnerable,
		MinSeverity:    cfg.MinSeverity,
		NoColor:        cfg.NoColor,
		Silent:         cfg.Silent,
		Verbose:        cfg.Verbose,
		JSON:           cfg.JSON,
		TechDetect:     researchCfg.TechDetect,
	}

	bar := ui.NewScanBar(os.Stderr, len(allSubdomains), showUI)
	progressFn := func(scanned, total, findings int) {
		bar.Tick("", scanned, findings)
	}

	e := engine.New(scanConfig)
	result := e.Scan(ctx, allSubdomains, progressFn)
	result.Target = target

	bar.Finish()

	if showUI {
		ui.PrintScanComplete(os.Stderr, cfg.NoColor, result.Stats.FindingsTotal,
			result.Duration.Round(1_000_000).String())
	}

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
