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
Use --no-crtsh to disable them.

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
	bruteCmd.Flags().BoolVar(&bruteCfg.AllSources, "all-sources", false, "Query all free passive OSINT sources")
	bruteCmd.Flags().StringVar(&bruteCfg.Sources, "sources", "", "Comma-separated OSINT sources to use (hackertarget,urlscan,wayback,rapiddns,anubis,alienvault,certspotter)")
	bruteCmd.Flags().BoolVar(&bruteCfg.TechDetect, "tech-detect", false, "Perform technology fingerprinting on discovered subdomains")
}

func runBrute(cmd *cobra.Command, args []string) error {
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

	// ── Live display panel ──────────────────────────────────────────────────
	var live *ui.LiveDisplay
	if showUI {
		live = ui.NewLiveDisplay(os.Stderr, cfg.NoColor)
		live.Header(target)
	}

	var allSubdomains []string

	// ── Stage 1: crt.sh Certificate Transparency ────────────────────────────
	if !bruteCfg.NoCrtsh {
		if showUI {
			stage := live.StartStage("crt.sh", fmt.Sprintf("Querying Certificate Transparency logs for %s…", target))
			ctSubdomains, err := discovery.QueryCrtSh(ctx, target)
			if err != nil {
				live.DoneStage(stage, false, fmt.Sprintf("crt.sh query failed: %v", err))
			} else {
				live.DoneStage(stage, true, fmt.Sprintf("%d subdomains found via CT logs", len(ctSubdomains)))
				allSubdomains = append(allSubdomains, ctSubdomains...)
			}
		} else {
			ctSubdomains, err := discovery.QueryCrtSh(ctx, target)
			if err != nil {
				if !cfg.Silent {
					fmt.Fprintf(os.Stderr, "[!] crt.sh query failed: %v\n", err)
				}
			} else {
				if !cfg.Silent {
					fmt.Fprintf(os.Stderr, "[*] Found %d subdomains from CT logs\n", len(ctSubdomains))
				}
				allSubdomains = append(allSubdomains, ctSubdomains...)
			}
		}
	} else {
		if showUI {
			live.SkipStage("crt.sh", "Certificate Transparency skipped (--no-crtsh)")
		}
	}

	// ── Stage 1.5: Multi-source OSINT ───────────────────────────────────────
	var osintSources []string
	if bruteCfg.Sources != "" {
		for _, s := range strings.Split(bruteCfg.Sources, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				osintSources = append(osintSources, s)
			}
		}
	} else if bruteCfg.AllSources {
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
			} else {
				if !cfg.Silent {
					fmt.Fprintf(os.Stderr, "[!] %s query failed: %v\n", src, err)
				}
			}
		}
	}

	// ── Stage 2: Wordlist Bruteforce ────────────────────────────────────────
	wordlistPath := bruteCfg.Wordlist
	if wordlistPath == "" {
		wordlistPath = "assets/wordlists/subdomains.txt"
	}

	if showUI {
		stage := live.StartStage("wordlist", fmt.Sprintf("Loading %s…", wordlistPath))
		wlSubdomains, err := discovery.LoadWordlist(wordlistPath, target)
		if err != nil {
			live.DoneStage(stage, false, fmt.Sprintf("Wordlist load failed: %v", err))
		} else {
			live.DoneStage(stage, true, fmt.Sprintf("%d candidates from wordlist", len(wlSubdomains)))
			allSubdomains = append(allSubdomains, wlSubdomains...)
		}
	} else {
		if !cfg.Silent {
			fmt.Fprintf(os.Stderr, "[*] Running wordlist enumeration with: %s\n", wordlistPath)
		}
		wlSubdomains, err := discovery.LoadWordlist(wordlistPath, target)
		if err != nil {
			if !cfg.Silent {
				fmt.Fprintf(os.Stderr, "[!] Wordlist load failed: %v\n", err)
			}
		} else {
			if !cfg.Silent {
				fmt.Fprintf(os.Stderr, "[*] %d candidates from wordlist\n", len(wlSubdomains))
			}
			allSubdomains = append(allSubdomains, wlSubdomains...)
		}
	}

	// ── Stage 3: Permutation Generation ────────────────────────────────────
	if bruteCfg.Permutations && len(allSubdomains) > 0 {
		if showUI {
			stage := live.StartStage("perms", fmt.Sprintf("Generating permutations from %d known subdomains…", len(allSubdomains)))
			perms := discovery.GeneratePermutations(allSubdomains, target)
			live.DoneStage(stage, true, fmt.Sprintf("%d permutations generated", len(perms)))
			allSubdomains = append(allSubdomains, perms...)
		} else {
			perms := discovery.GeneratePermutations(allSubdomains, target)
			if !cfg.Silent {
				fmt.Fprintf(os.Stderr, "[*] %d permutations generated\n", len(perms))
			}
			allSubdomains = append(allSubdomains, perms...)
		}
	} else if showUI {
		live.SkipStage("perms", "Permutation generation skipped (use --permutations to enable)")
	}

	// ── Deduplicate ─────────────────────────────────────────────────────────
	allSubdomains = discovery.Deduplicate(allSubdomains)

	if len(allSubdomains) == 0 {
		fmt.Fprintln(os.Stderr, "[!] No subdomains to scan.")
		return nil
	}

	// ── Stage 4: Scanning footer ────────────────────────────────────────────
	if showUI {
		live.Footer(len(allSubdomains))
	} else if !cfg.Silent {
		fmt.Fprintf(os.Stderr, "[*] Scanning %d unique subdomains...\n\n", len(allSubdomains))
	}

	// ── Build scan config & run ─────────────────────────────────────────────
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
		NoVerify:       cfg.NoVerify,
		OnlyVulnerable: cfg.OnlyVulnerable,
		MinSeverity:    cfg.MinSeverity,
		NoColor:        cfg.NoColor,
		Silent:         cfg.Silent,
		Verbose:        cfg.Verbose,
		JSON:           cfg.JSON,
		TechDetect:     bruteCfg.TechDetect,
	}

	// Progress bar for the scan phase
	bar := ui.NewScanBar(os.Stderr, len(allSubdomains), showUI)

	progressFn := func(scanned, total, findings int) {
		// We don't have the current domain here — pass empty string
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
