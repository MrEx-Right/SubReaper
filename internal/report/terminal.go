package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/MrEx-Right/SubReaper/internal/models"
	"github.com/fatih/color"
)

// TerminalReporter produces rich, colored terminal output.
type TerminalReporter struct {
	NoColor bool
	Verbose bool // list scan errors
}

// severity color map
var severityColor = map[models.Severity]*color.Color{
	models.SeverityInfo:     color.New(color.FgCyan),
	models.SeverityLow:      color.New(color.FgBlue),
	models.SeverityMedium:   color.New(color.FgYellow),
	models.SeverityHigh:     color.New(color.FgRed),
	models.SeverityCritical: color.New(color.FgRed, color.Bold),
}

var severityBadge = map[models.Severity]string{
	models.SeverityInfo:     "[ INFO     ]",
	models.SeverityLow:      "[ LOW      ]",
	models.SeverityMedium:   "[ MEDIUM   ]",
	models.SeverityHigh:     "[ HIGH     ]",
	models.SeverityCritical: "[ CRITICAL ]",
}

// Write outputs the full scan result to the writer.
func (r *TerminalReporter) Write(w io.Writer, result *models.ScanResult) error {
	if r.NoColor {
		color.NoColor = true
	}

	bold := color.New(color.Bold)
	dim := color.New(color.Faint)
	green := color.New(color.FgGreen)
	cyan := color.New(color.FgCyan)

	// ── Summary header ────────────────────────────────────────────────────────
	fmt.Fprintln(w)
	bold.Fprintf(w, "  Scan complete\n")
	dim.Fprintf(w, "  Duration  : %s\n", result.Duration.Round(1000000))
	dim.Fprintf(w, "  Domains   : %d scanned\n", result.Stats.DomainsScanned)
	dim.Fprintf(w, "  Findings  : %d total\n", result.Stats.FindingsTotal)
	if len(result.Errors) > 0 {
		if r.Verbose {
			dim.Fprintf(w, "  Errors    : %d\n", len(result.Errors))
			for _, e := range result.Errors {
				dim.Fprintf(w, "    - %s: %s\n", e.Domain, e.Message)
			}
		} else {
			dim.Fprintf(w, "  Errors    : %d (use -v for details)\n", len(result.Errors))
		}
	}
	if result.Interrupted {
		color.New(color.FgYellow).Fprintf(w, "  Status    : interrupted, partial results\n")
	}
	fmt.Fprintln(w)

	if len(result.Findings) == 0 {
		green.Fprintln(w, "  No dangling subdomains found.")
		fmt.Fprintln(w)
		return nil
	}

	// Group findings by severity (highest first)
	grouped := groupBySeverity(result.Findings)
	order := []models.Severity{
		models.SeverityCritical,
		models.SeverityHigh,
		models.SeverityMedium,
		models.SeverityLow,
		models.SeverityInfo,
	}

	for _, sev := range order {
		findings := grouped[sev]
		if len(findings) == 0 {
			continue
		}

		col := severityColor[sev]
		badge := severityBadge[sev]

		for _, f := range findings {
			// Finding header
			col.Fprintf(w, "%s %s\n", badge, f.Subdomain)

			// Clickable links for quick manual verification
			cyan.Fprintf(w, "  ├─ Subdomain URL : http://%s | https://%s\n", f.Subdomain, f.Subdomain)

			var danglingTarget string
			if f.Chain != nil {
				for _, hop := range f.Chain.Hops {
					if string(hop.RecordType) == "CNAME" && (!hop.Resolved || hop.NXDOMAIN) {
						danglingTarget = strings.TrimSuffix(hop.Value, ".")
						break
					}
				}
			}
			if danglingTarget != "" {
				cyan.Fprintf(w, "  ├─ Dangling CNAME: http://%s | https://%s\n", danglingTarget, danglingTarget)
			}

			// DNS chain
			if f.Chain != nil && len(f.Chain.Hops) > 0 {
				cyan.Fprintf(w, "  ├─ DNS Chain\n")
				for i, hop := range f.Chain.Hops {
					connector := "│  ├─"
					if i == len(f.Chain.Hops)-1 {
						connector = "│  └─"
					}
					status := ""
					if hop.NXDOMAIN {
						status = color.RedString(" [NXDOMAIN]")
					} else if !hop.Resolved {
						status = color.YellowString(" [unresolved]")
					}
					fmt.Fprintf(w, "  %s %s %s → %s%s\n",
						connector,
						dim.Sprint(string(hop.RecordType)),
						hop.Name,
						hop.Value,
						status,
					)
				}
			}

			if len(f.IPs) > 0 {
				dim.Fprintf(w, "  ├─ IPs           : %s\n", joinIPs(f))
			}
			if s := probeSummary(f); s != "" {
				dim.Fprintf(w, "  ├─ HTTP          : %s\n", s)
			}
			if len(f.Technologies) > 0 {
				dim.Fprintf(w, "  ├─ Technologies  : %s\n", strings.Join(f.Technologies, ", "))
			}
			for _, t := range f.TXTRecords {
				if t.Kind == "spf" || t.Kind == "dmarc" {
					dim.Fprintf(w, "  ├─ %-14s: %s\n", strings.ToUpper(t.Kind), t.Raw)
				}
			}

			// Provider
			if f.Provider != nil && f.Provider.IsIdentified() {
				status := ""
				if f.Provider.Status != "" {
					status = ", " + strings.ReplaceAll(string(f.Provider.Status), "_", " ")
				}
				cyan.Fprintf(w, "  ├─ Provider      : %s (confidence: %d%%%s)\n",
					bold.Sprint(f.Provider.ProviderName),
					f.Provider.Confidence, status,
				)
				if f.Provider.ClaimVerified {
					color.New(color.BgRed, color.FgHiWhite, color.Bold).Fprintf(w, "  ├─ [TAKEOVER READY] RESOURCE IS UNCLAIMED AND VULNERABLE \n")
				}
				if f.Provider.ClaimURL != "" {
					color.New(color.FgHiGreen, color.Bold).Fprintf(w, "  ├─ Claim Here    : %s\n", f.Provider.ClaimURL)
				}
				if f.Provider.TakeoverWriteup != "" {
					dim.Fprintf(w, "  ├─ Reference     : %s\n", f.Provider.TakeoverWriteup)
				}
			}

			// Signals (verbose would show all; always show count)
			if f.Provider != nil && len(f.Provider.Signals) > 0 {
				dim.Fprintf(w, "  ├─ Signals       : %s\n",
					formatSignals(f.Provider.Signals))
			}

			// Description
			if f.Description != "" {
				fmt.Fprintf(w, "  ├─ Description   : %s\n", f.Description)
			}

			// Remediation
			if f.Remediation != "" {
				fmt.Fprintf(w, "  └─ Remediation   : %s\n", f.Remediation)
			}

			fmt.Fprintln(w)
		}
	}

	// Severity summary table
	bold.Fprintf(w, "  Severity Summary\n")
	for _, sev := range order {
		count := result.Stats.Byseverity[sev]
		if count == 0 {
			continue
		}
		col := severityColor[sev]
		col.Fprintf(w, "  %-10s %d\n", sev.String(), count)
	}
	fmt.Fprintln(w)

	return nil
}

// groupBySeverity groups findings into a map keyed by Severity.
func groupBySeverity(findings []*models.Finding) map[models.Severity][]*models.Finding {
	grouped := make(map[models.Severity][]*models.Finding)
	for _, f := range findings {
		grouped[f.Severity] = append(grouped[f.Severity], f)
	}
	return grouped
}

// joinIPs formats the resolved IPs of a finding.
func joinIPs(f *models.Finding) string {
	parts := make([]string, 0, len(f.IPs))
	for _, ip := range f.IPs {
		parts = append(parts, ip.String())
	}
	return strings.Join(parts, ", ")
}

// probeSummary formats "url → status" for each HTTP probe that answered.
func probeSummary(f *models.Finding) string {
	var parts []string
	for _, p := range f.HTTPProbes {
		if p == nil || p.Error != "" {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s → %d", p.URL, p.StatusCode))
	}
	return strings.Join(parts, " | ")
}

// formatSignals returns a compact one-liner of signal type names.
func formatSignals(signals []models.Signal) string {
	types := make(map[string]struct{})
	for _, s := range signals {
		types[string(s.Type)] = struct{}{}
	}
	parts := make([]string, 0, len(types))
	for t := range types {
		parts = append(parts, t)
	}
	return strings.Join(parts, ", ")
}
