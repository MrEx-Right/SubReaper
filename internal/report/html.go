package report

import (
	"fmt"
	"html"
	"io"
	"strings"
	"time"

	"github.com/MrEx-Right/SubReaper/internal/models"
)

// HTMLReporter produces a self-contained, single-file HTML report.
// No external dependencies (CDN, fonts via data URIs or system fonts).
type HTMLReporter struct{}

// Write serializes the ScanResult to a self-contained HTML file.
func (r *HTMLReporter) Write(w io.Writer, result *models.ScanResult) error {
	ts := time.Now().Format("2006-01-02 15:04:05")
	header := strings.ReplaceAll(htmlHeader, "{{.TS}}", ts)
	_, err := io.WriteString(w, header)
	if err != nil {
		return err
	}

	// Stats bar
	critical := result.Stats.Byseverity[models.SeverityCritical]
	high := result.Stats.Byseverity[models.SeverityHigh]
	medium := result.Stats.Byseverity[models.SeverityMedium]
	low := result.Stats.Byseverity[models.SeverityLow]
	info := result.Stats.Byseverity[models.SeverityInfo]

	fmt.Fprintf(w, `
  <div class="stats-bar">
    <div class="stat"><span class="num">%d</span><span class="label">Scanned</span></div>
    <div class="stat"><span class="num">%d</span><span class="label">Total Findings</span></div>
    <div class="stat critical"><span class="num">%d</span><span class="label">Critical</span></div>
    <div class="stat high"><span class="num">%d</span><span class="label">High</span></div>
    <div class="stat medium"><span class="num">%d</span><span class="label">Medium</span></div>
    <div class="stat low"><span class="num">%d</span><span class="label">Low</span></div>
    <div class="stat info"><span class="num">%d</span><span class="label">Info</span></div>
    <div class="stat"><span class="num">%s</span><span class="label">Duration</span></div>
  </div>
`,
		result.Stats.DomainsScanned,
		result.Stats.FindingsTotal,
		critical, high, medium, low, info,
		result.Duration.Round(1000000),
	)

	if len(result.Findings) == 0 {
		fmt.Fprintln(w, `<div class="no-findings">✅ No dangling subdomains found.</div>`)
	} else {
		// Filter controls
		fmt.Fprintln(w, `<div class="controls">
  <label>Filter by severity:</label>
  <button onclick="filterSeverity('ALL')" class="btn active" id="btn-ALL">All</button>
  <button onclick="filterSeverity('CRITICAL')" class="btn critical" id="btn-CRITICAL">Critical</button>
  <button onclick="filterSeverity('HIGH')" class="btn high" id="btn-HIGH">High</button>
  <button onclick="filterSeverity('MEDIUM')" class="btn medium" id="btn-MEDIUM">Medium</button>
  <button onclick="filterSeverity('LOW')" class="btn low" id="btn-LOW">Low</button>
  <button onclick="filterSeverity('INFO')" class="btn info" id="btn-INFO">Info</button>
</div>`)

		// Findings table
		fmt.Fprintln(w, `<table id="findings-table">
<thead>
  <tr>
    <th>Subdomain</th>
    <th>Severity</th>
    <th>Type</th>
    <th>Provider</th>
    <th>Confidence</th>
    <th>Claim Verified</th>
  </tr>
</thead>
<tbody>`)

		for _, f := range result.Findings {
			provider := "-"
			confidence := "-"
			claimVerified := "No"
			claimClass := ""

			if f.Provider != nil && f.Provider.IsIdentified() {
				provider = html.EscapeString(f.Provider.ProviderName)
				confidence = fmt.Sprintf("%d%%", f.Provider.Confidence)
			}
			if f.Provider != nil && f.Provider.ClaimVerified {
				claimVerified = "YES"
				claimClass = "claim-yes"
			}

			sevStr := f.Severity.String()
			fmt.Fprintf(w, `<tr class="row" data-severity="%s" onclick="toggleDetail(this)">
  <td><code>%s</code></td>
  <td><span class="badge %s">%s</span></td>
  <td>%s</td>
  <td>%s</td>
  <td>%s</td>
  <td class="%s">%s</td>
</tr>
<tr class="detail-row" data-severity="%s" style="display:none">
  <td colspan="6">%s</td>
</tr>
`,
				sevStr,
				html.EscapeString(f.Subdomain),
				strings.ToLower(sevStr), sevStr,
				html.EscapeString(string(f.Type)),
				provider,
				confidence,
				claimClass, claimVerified,
				sevStr,
				buildHTMLDetail(f),
			)
		}
		fmt.Fprintln(w, `</tbody></table>`)
	}

	fmt.Fprint(w, htmlFooter)
	return nil
}

// buildHTMLDetail builds the expandable detail panel for a finding.
func buildHTMLDetail(f *models.Finding) string {
	var sb strings.Builder

	sb.WriteString(`<div class="detail">`)

	if f.Description != "" {
		sb.WriteString(fmt.Sprintf("<p><strong>Description:</strong> %s</p>", html.EscapeString(f.Description)))
	}

	if f.Chain != nil && len(f.Chain.Hops) > 0 {
		sb.WriteString("<p><strong>DNS Chain:</strong></p><pre>")
		for _, hop := range f.Chain.Hops {
			status := ""
			if hop.NXDOMAIN {
				status = " [NXDOMAIN]"
			} else if !hop.Resolved {
				status = " [unresolved]"
			}
			sb.WriteString(html.EscapeString(
				fmt.Sprintf("%s %s → %s%s\n", hop.Name, hop.RecordType, hop.Value, status),
			))
		}
		sb.WriteString("</pre>")
	}

	if f.Provider != nil && len(f.Provider.Signals) > 0 {
		sb.WriteString("<p><strong>Signals:</strong></p><ul>")
		for _, s := range f.Provider.Signals {
			sb.WriteString(fmt.Sprintf("<li><code>%s</code>: %s (+%d)</li>",
				html.EscapeString(string(s.Type)),
				html.EscapeString(s.Description),
				s.Points,
			))
		}
		sb.WriteString("</ul>")
	}

	if f.Remediation != "" {
		sb.WriteString(fmt.Sprintf("<p><strong>Remediation:</strong> %s</p>", html.EscapeString(f.Remediation)))
	}

	if f.Provider != nil && f.Provider.TakeoverWriteup != "" {
		sb.WriteString(fmt.Sprintf(
			`<p><strong>Reference:</strong> <a href="%s" target="_blank" rel="noopener">%s</a></p>`,
			html.EscapeString(f.Provider.TakeoverWriteup),
			html.EscapeString(f.Provider.TakeoverWriteup),
		))
	}

	sb.WriteString("</div>")
	return sb.String()
}

const htmlHeader = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SubReaper Report — {{.TS}}</title>
<style>
  :root {
    --bg: #0d1117;
    --surface: #161b22;
    --border: #30363d;
    --text: #e6edf3;
    --dim: #8b949e;
    --critical: #ff4444;
    --high: #ff6b35;
    --medium: #f0b429;
    --low: #4a9eff;
    --info: #6e7681;
    --green: #3fb950;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', monospace; padding: 2rem; }
  h1 { font-size: 1.8rem; color: var(--critical); margin-bottom: 0.25rem; }
  .sub { color: var(--dim); margin-bottom: 2rem; font-size: 0.9rem; }
  .stats-bar { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }
  .stat { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.5rem; display: flex; flex-direction: column; align-items: center; min-width: 100px; }
  .stat .num { font-size: 2rem; font-weight: bold; }
  .stat .label { font-size: 0.75rem; color: var(--dim); text-transform: uppercase; letter-spacing: 0.05em; margin-top: 0.25rem; }
  .stat.critical .num { color: var(--critical); }
  .stat.high .num { color: var(--high); }
  .stat.medium .num { color: var(--medium); }
  .stat.low .num { color: var(--low); }
  .stat.info .num { color: var(--info); }
  .controls { margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
  .controls label { color: var(--dim); font-size: 0.85rem; }
  .btn { border: 1px solid var(--border); background: var(--surface); color: var(--text); padding: 0.3rem 0.8rem; border-radius: 20px; cursor: pointer; font-size: 0.8rem; transition: all 0.15s; }
  .btn:hover, .btn.active { background: var(--border); }
  .btn.critical { border-color: var(--critical); color: var(--critical); }
  .btn.high { border-color: var(--high); color: var(--high); }
  .btn.medium { border-color: var(--medium); color: var(--medium); }
  .btn.low { border-color: var(--low); color: var(--low); }
  table { width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 8px; overflow: hidden; }
  th { background: var(--border); color: var(--dim); text-align: left; padding: 0.75rem 1rem; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }
  td { padding: 0.75rem 1rem; border-bottom: 1px solid var(--border); font-size: 0.9rem; }
  .row { cursor: pointer; transition: background 0.1s; }
  .row:hover { background: rgba(255,255,255,0.04); }
  code { background: rgba(255,255,255,0.08); padding: 0.1em 0.4em; border-radius: 4px; font-size: 0.85em; }
  .badge { padding: 0.2em 0.6em; border-radius: 4px; font-size: 0.75em; font-weight: bold; text-transform: uppercase; }
  .badge.critical { background: rgba(255,68,68,0.15); color: var(--critical); }
  .badge.high { background: rgba(255,107,53,0.15); color: var(--high); }
  .badge.medium { background: rgba(240,180,41,0.15); color: var(--medium); }
  .badge.low { background: rgba(74,158,255,0.15); color: var(--low); }
  .badge.info { background: rgba(110,118,129,0.15); color: var(--info); }
  .claim-yes { color: var(--critical); font-weight: bold; }
  .detail { padding: 1rem; background: rgba(255,255,255,0.02); border-left: 3px solid var(--border); }
  .detail p { margin: 0.5rem 0; line-height: 1.6; }
  .detail pre { background: rgba(0,0,0,0.3); padding: 0.75rem; border-radius: 4px; font-size: 0.8rem; overflow-x: auto; margin: 0.5rem 0; }
  .detail ul { margin: 0.5rem 0 0.5rem 1.5rem; }
  .detail li { margin: 0.25rem 0; font-size: 0.85rem; }
  .detail a { color: var(--low); }
  .no-findings { color: var(--green); font-size: 1.1rem; margin-top: 2rem; }
</style>
</head>
<body>
<h1>⚔ SubReaper</h1>
<div class="sub">Subdomain Takeover Scan Report &mdash; Generated {{.TS}}</div>
`

const htmlFooter = `
<script>
function filterSeverity(sev) {
  document.querySelectorAll('.btn').forEach(b => b.classList.remove('active'));
  document.getElementById('btn-' + sev).classList.add('active');
  document.querySelectorAll('tr.row, tr.detail-row').forEach(row => {
    if (sev === 'ALL' || row.dataset.severity === sev) {
      if (!row.classList.contains('detail-row')) row.style.display = '';
    } else {
      row.style.display = 'none';
      if (row.classList.contains('detail-row')) row.style.display = 'none';
    }
  });
}
function toggleDetail(row) {
  const next = row.nextElementSibling;
  if (next && next.classList.contains('detail-row')) {
    next.style.display = next.style.display === 'none' ? 'table-row' : 'none';
  }
}
</script>
</body>
</html>
`
