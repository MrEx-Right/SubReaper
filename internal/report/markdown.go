package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/MrEx-Right/SubReaper/internal/models"
)

// MarkdownReporter produces a Markdown report.
type MarkdownReporter struct{}

// Write serializes the ScanResult to Markdown.
func (r *MarkdownReporter) Write(w io.Writer, result *models.ScanResult) error {
	fmt.Fprintf(w, "# SubReaper Scan Report\n\n")
	fmt.Fprintf(w, "| Field | Value |\n|---|---|\n")
	fmt.Fprintf(w, "| Duration | %s |\n", result.Duration)
	fmt.Fprintf(w, "| Domains Scanned | %d |\n", result.Stats.DomainsScanned)
	fmt.Fprintf(w, "| Findings | %d |\n\n", result.Stats.FindingsTotal)

	if len(result.Findings) == 0 {
		fmt.Fprintln(w, "> ✅ No dangling subdomains found.")
		return nil
	}

	// Summary table
	fmt.Fprintf(w, "## Findings Summary\n\n")
	fmt.Fprintf(w, "| Subdomain | Severity | Type | Provider | Confidence |\n")
	fmt.Fprintf(w, "|---|---|---|---|---|\n")
	for _, f := range result.Findings {
		provider := "-"
		confidence := "-"
		if f.Provider != nil && f.Provider.IsIdentified() {
			provider = f.Provider.ProviderName
			confidence = fmt.Sprintf("%d%%", f.Provider.Confidence)
		}
		fmt.Fprintf(w, "| `%s` | **%s** | %s | %s | %s |\n",
			f.Subdomain, f.Severity, f.Type, provider, confidence)
	}
	fmt.Fprintln(w)

	// Detail sections
	fmt.Fprintf(w, "## Finding Details\n\n")
	for i, f := range result.Findings {
		fmt.Fprintf(w, "### %d. %s\n\n", i+1, f.Subdomain)
		fmt.Fprintf(w, "- **Severity**: %s\n", f.Severity)
		fmt.Fprintf(w, "- **Type**: %s\n", f.Type)
		if f.Description != "" {
			fmt.Fprintf(w, "- **Description**: %s\n", f.Description)
		}

		if f.Chain != nil && len(f.Chain.Hops) > 0 {
			fmt.Fprintf(w, "\n**DNS Chain**\n\n```\n")
			for _, hop := range f.Chain.Hops {
				status := ""
				if hop.NXDOMAIN {
					status = " [NXDOMAIN]"
				} else if !hop.Resolved {
					status = " [unresolved]"
				}
				fmt.Fprintf(w, "%s %s → %s%s\n", hop.Name, hop.RecordType, hop.Value, status)
			}
			fmt.Fprintf(w, "```\n")
		}

		if f.Provider != nil && f.Provider.IsIdentified() {
			fmt.Fprintf(w, "\n**Provider**: %s (confidence: %d%%)\n", f.Provider.ProviderName, f.Provider.Confidence)
			if f.Provider.ClaimVerified {
				fmt.Fprintf(w, "\n> ⚠️ **Claim check VERIFIED** — resource is confirmed unclaimed.\n")
			}
			if len(f.Provider.Signals) > 0 {
				fmt.Fprintf(w, "\n**Signals**:\n")
				for _, s := range f.Provider.Signals {
					fmt.Fprintf(w, "- `%s`: %s (+%d)\n", s.Type, s.Description, s.Points)
				}
			}
			if f.Provider.TakeoverWriteup != "" {
				fmt.Fprintf(w, "\n**Reference**: %s\n", f.Provider.TakeoverWriteup)
			}
		}

		if f.Remediation != "" {
			fmt.Fprintf(w, "\n**Remediation**: %s\n", f.Remediation)
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w, strings.Repeat("---", 20))
		fmt.Fprintln(w)
	}

	return nil
}
