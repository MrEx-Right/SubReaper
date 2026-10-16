package report

import (
	"encoding/json"
	"io"
	"time"

	"github.com/MrEx-Right/SubReaper/internal/models"
)

// JSONReporter produces machine-readable JSON output.
type JSONReporter struct{}

// jsonOutput is the top-level JSON structure written by JSONReporter.
type jsonOutput struct {
	Target      string        `json:"target,omitempty"`
	StartedAt   time.Time     `json:"started_at"`
	Duration    string        `json:"duration"`
	Stats       jsonStats     `json:"stats"`
	Interrupted bool          `json:"interrupted,omitempty"`
	Findings    []jsonFinding `json:"findings"`
	Errors      []jsonError   `json:"errors,omitempty"`
}

type jsonStats struct {
	DomainsScanned int            `json:"domains_scanned"`
	FindingsTotal  int            `json:"findings_total"`
	BySeverity     map[string]int `json:"by_severity"`
}

type jsonFinding struct {
	Subdomain    string        `json:"subdomain"`
	Severity     string        `json:"severity"`
	Type         string        `json:"type"`
	Chain        []jsonHop     `json:"dns_chain,omitempty"`
	Provider     *jsonProvider `json:"provider,omitempty"`
	IPs          []string      `json:"ips,omitempty"`
	HTTP         []jsonProbe   `json:"http,omitempty"`
	Technologies []string      `json:"technologies,omitempty"`
	TXTRecords   []jsonTXT     `json:"txt_records,omitempty"`
	Description  string        `json:"description,omitempty"`
	Remediation  string        `json:"remediation,omitempty"`
	DiscoveredAt time.Time     `json:"discovered_at"`
}

type jsonHop struct {
	Name       string `json:"name"`
	RecordType string `json:"record_type"`
	Value      string `json:"value,omitempty"`
	Resolved   bool   `json:"resolved"`
	NXDOMAIN   bool   `json:"nxdomain,omitempty"`
}

type jsonProvider struct {
	Name          string       `json:"name"`
	Status        string       `json:"status,omitempty"`
	Confidence    int          `json:"confidence"`
	Identified    bool         `json:"identified"`
	ClaimVerified bool         `json:"claim_verified"`
	Signals       []jsonSignal `json:"signals"`
	Writeup       string       `json:"writeup,omitempty"`
	ClaimURL      string       `json:"claim_url,omitempty"`
}

type jsonProbe struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code,omitempty"`
	Server     string `json:"server,omitempty"`
	TLSSubject string `json:"tls_subject,omitempty"`
	Error      string `json:"error,omitempty"`
}

type jsonTXT struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
	Issue string `json:"issue,omitempty"`
}

type jsonSignal struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Points      int    `json:"points"`
}

type jsonError struct {
	Domain  string `json:"domain"`
	Stage   string `json:"stage"`
	Message string `json:"message"`
}

// Write serializes the ScanResult to JSON.
func (r *JSONReporter) Write(w io.Writer, result *models.ScanResult) error {
	out := jsonOutput{
		StartedAt:   result.StartedAt,
		Duration:    result.Duration.String(),
		Interrupted: result.Interrupted,
	}

	// Stats
	bySev := make(map[string]int)
	for sev, count := range result.Stats.Byseverity {
		bySev[sev.String()] = count
	}
	out.Stats = jsonStats{
		DomainsScanned: result.Stats.DomainsScanned,
		FindingsTotal:  result.Stats.FindingsTotal,
		BySeverity:     bySev,
	}

	// Findings
	for _, f := range result.Findings {
		jf := jsonFinding{
			Subdomain:    f.Subdomain,
			Severity:     f.Severity.String(),
			Type:         string(f.Type),
			Description:  f.Description,
			Remediation:  f.Remediation,
			DiscoveredAt: f.DiscoveredAt,
		}
		if f.Chain != nil {
			for _, h := range f.Chain.Hops {
				jf.Chain = append(jf.Chain, jsonHop{
					Name:       h.Name,
					RecordType: string(h.RecordType),
					Value:      h.Value,
					Resolved:   h.Resolved,
					NXDOMAIN:   h.NXDOMAIN,
				})
			}
		}
		if f.Provider != nil && f.Provider.ProviderName != "" {
			jp := &jsonProvider{
				Name:          f.Provider.ProviderName,
				Status:        string(f.Provider.Status),
				Confidence:    f.Provider.Confidence,
				Identified:    f.Provider.IsIdentified(),
				ClaimVerified: f.Provider.ClaimVerified,
				Writeup:       f.Provider.TakeoverWriteup,
				ClaimURL:      f.Provider.ClaimURL,
			}
			for _, s := range f.Provider.Signals {
				jp.Signals = append(jp.Signals, jsonSignal{
					Type:        string(s.Type),
					Description: s.Description,
					Points:      s.Points,
				})
			}
			jf.Provider = jp
		}
		for _, ip := range f.IPs {
			jf.IPs = append(jf.IPs, ip.String())
		}
		for _, p := range f.HTTPProbes {
			if p == nil {
				continue
			}
			jf.HTTP = append(jf.HTTP, jsonProbe{
				URL:        p.URL,
				StatusCode: p.StatusCode,
				Server:     p.Header("Server"),
				TLSSubject: p.TLSSubject,
				Error:      p.Error,
			})
		}
		jf.Technologies = f.Technologies
		for _, t := range f.TXTRecords {
			jf.TXTRecords = append(jf.TXTRecords, jsonTXT{Kind: t.Kind, Value: t.Raw, Issue: t.Issue})
		}
		out.Findings = append(out.Findings, jf)
	}

	// Errors
	for _, e := range result.Errors {
		out.Errors = append(out.Errors, jsonError{
			Domain:  e.Domain,
			Stage:   e.Stage,
			Message: e.Message,
		})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
