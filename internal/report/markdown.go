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
	fmt.Fprintf(w, "| Findings | %d |\n", result.Stats.FindingsTotal)
	fmt.Fprintf(w, "| Errors | %d |\n", len(result.Errors))
	if result.Interrupted {
		fmt.Fprintf(w, "| Status | interrupted, partial results |\n")
	}
	fmt.Fprintln(w)

	if len(result.Findings) == 0 {
		fmt.Fprintln(w, "> ✅ No dangling subdomains found.")
		writeMarkdownErrors(w, result)
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

		if len(f.IPs) > 0 {
			fmt.Fprintf(w, "\n**IPs**: %s\n", joinIPs(f))
		}
		if s := probeSummary(f); s != "" {
			fmt.Fprintf(w, "\n**HTTP**: %s\n", s)
		}
		if len(f.Technologies) > 0 {
			fmt.Fprintf(w, "\n**Technologies**: %s\n", strings.Join(f.Technologies, ", "))
		}
		if len(f.TXTRecords) > 0 {
			fmt.Fprintf(w, "\n**TXT records**:\n")
			for _, t := range f.TXTRecords {
				fmt.Fprintf(w, "- `%s`: `%s`\n", t.Kind, t.Raw)
			}
		}

		if f.Provider != nil && f.Provider.IsIdentified() {
			fmt.Fprintf(w, "\n**Provider**: %s (confidence: %d%%, %s)\n", f.Provider.ProviderName, f.Provider.Confidence, f.Provider.Status)
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

	writeMarkdownErrors(w, result)
	return nil
}

func writeMarkdownErrors(w io.Writer, result *models.ScanResult) {
	if len(result.Errors) == 0 {
		return
	}
	fmt.Fprintf(w, "## Scan Errors\n\n")
	for _, e := range result.Errors {
		fmt.Fprintf(w, "- `%s`: %s\n", e.Domain, e.Message)
	}
	fmt.Fprintln(w)
}
