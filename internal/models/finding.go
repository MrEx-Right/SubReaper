// Package models defines the core data structures used throughout SubReaper.
package models

import (
	"fmt"
	"net"
	"time"
)

// Severity represents the risk level of a finding.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// String returns the string representation of a Severity.
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// DNSRecordType represents a DNS record type.
type DNSRecordType string

const (
	RecordCNAME DNSRecordType = "CNAME"
	RecordA     DNSRecordType = "A"
	RecordAAAA  DNSRecordType = "AAAA"
	RecordNS    DNSRecordType = "NS"
	RecordMX    DNSRecordType = "MX"
)

// DNSHop represents a single hop in a DNS resolution chain.
type DNSHop struct {
	Name       string        // The domain name at this hop
	RecordType DNSRecordType // The record type that led to the next hop
	Value      string        // The resolved value (next CNAME, IP, etc.)
	Resolved   bool          // Whether this hop resolved successfully
	NXDOMAIN   bool          // Whether this hop returned NXDOMAIN
}

// String formats a DNS hop for display.
func (h DNSHop) String() string {
	status := "ok"
	if h.NXDOMAIN {
		status = "NXDOMAIN"
	} else if !h.Resolved {
		status = "unresolved"
	}
	return fmt.Sprintf("%s %s → %s [%s]", h.Name, h.RecordType, h.Value, status)
}

// DNSChain represents the full DNS resolution chain for a target domain.
type DNSChain struct {
	Root          string   // The original target domain
	Hops          []DNSHop // All hops in order
	DanglingPoint int      // Index of the hop where resolution breaks (-1 if none)
	IsWildcard    bool     // Whether the root domain has a wildcard record
	HasLoop       bool     // Whether a CNAME loop was detected
}

// IsDangling returns true if the chain has an identified dangling point.
func (c *DNSChain) IsDangling() bool {
	return c.DanglingPoint >= 0
}

// DanglingHop returns the hop where resolution breaks, or nil.
func (c *DNSChain) DanglingHop() *DNSHop {
	if !c.IsDangling() || c.DanglingPoint >= len(c.Hops) {
		return nil
	}
	h := c.Hops[c.DanglingPoint]
	return &h
}

// FinalCNAME returns the last CNAME value in the chain before the dangling point.
func (c *DNSChain) FinalCNAME() string {
	for i := c.DanglingPoint - 1; i >= 0; i-- {
		if c.Hops[i].RecordType == RecordCNAME {
			return c.Hops[i].Value
		}
	}
	return ""
}

// HTTPProbe holds the result of an HTTP/HTTPS probe against a target.
type HTTPProbe struct {
	URL           string              // The probed URL
	StatusCode    int                 // HTTP status code
	Headers       map[string][]string // Response headers
	Body          []byte              // First 4KB of response body (for signal extraction)
	RedirectChain []string            // Redirect URLs followed
	TLSSubject    string              // TLS certificate subject (CN)
	TLSIssuer     string              // TLS certificate issuer
	ResponseTime  time.Duration       // Round-trip time
	Error         string              // Non-empty if the probe failed
}

// Header returns the first value of a response header (case-insensitive key).
func (p *HTTPProbe) Header(key string) string {
	for k, vals := range p.Headers {
		if equalFold(k, key) && len(vals) > 0 {
			return vals[0]
		}
	}
	return ""
}

// HasHeader returns true if the response contains a header with the given key.
func (p *HTTPProbe) HasHeader(key string) bool {
	return p.Header(key) != ""
}

// BodyString returns the response body as a string.
func (p *HTTPProbe) BodyString() string {
	return string(p.Body)
}

// equalFold is a simple ASCII case-insensitive comparison.
func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 32
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// SignalType categorizes the evidence used to identify a provider.
type SignalType string

const (
	SignalCNAMESuffix   SignalType = "cname_suffix"
	SignalIPRange       SignalType = "ip_range"
	SignalTLSCert       SignalType = "tls_cert"
	SignalHeader        SignalType = "header"
	SignalBodyMarker    SignalType = "body_marker"
	SignalStatusCode    SignalType = "status_code"
	SignalClaimVerified SignalType = "claim_verified"
)

// Signal represents a single piece of evidence contributing to a provider match.
type Signal struct {
	Type        SignalType
	Description string
	Points      int
}

// ProviderMatch holds the result of provider fingerprinting for a target.
type ProviderMatch struct {
	ProviderName    string   // Identified provider name (empty if unknown)
	Confidence      int      // Confidence score (0–100)
	Signals         []Signal // Evidence signals
	ClaimVerified   bool     // Whether the resource was confirmed claimable
	TakeoverWriteup string   // URL to a public writeup/PoC
	ClaimURL        string   // 1-click platform URL to claim the resource
}

// IsIdentified returns true if a provider was matched with sufficient confidence.
func (m *ProviderMatch) IsIdentified() bool {
	return m.ProviderName != "" && m.Confidence >= 60
}

// TXTRecord holds analysed data from a DNS TXT record.
type TXTRecord struct {
	Raw    string // Raw TXT record value
	Kind   string // Detected kind: spf | dmarc | dkim | verification | unknown
	Domain string // Referenced domain (for SPF includes, DMARC rua etc.)
	Issue  string // Non-empty if a security issue was detected
}

// Finding is the top-level result of scanning a single target domain.
type Finding struct {
	Target       string         // The scanned domain
	Subdomain    string         // The specific subdomain (may equal Target)
	Severity     Severity       // Overall severity
	Type         FindingType    // Classification of the finding
	Chain        *DNSChain      // DNS chain analysis result
	HTTPProbes   []*HTTPProbe   // HTTP/HTTPS probe results
	Provider     *ProviderMatch // Provider fingerprinting result
	TXTRecords   []TXTRecord    // Analysed TXT/SPF/DMARC records
	Technologies []string       // Detected technologies (e.g. "WordPress", "Nginx")
	SourceHints  []string       // OSINT sources that discovered this subdomain
	Description  string         // Human-readable summary
	Remediation  string         // Suggested remediation
	DiscoveredAt time.Time      // When the finding was produced
	IPs          []net.IP       // Resolved IPs (if any)
}

// FindingType classifies the nature of a finding.
type FindingType string

const (
	FindingCNAMEDangling    FindingType = "CNAME_DANGLING"
	FindingNSDangling       FindingType = "NS_DANGLING"
	FindingMXDangling       FindingType = "MX_DANGLING"
	FindingIPUnresponsive   FindingType = "IP_UNRESPONSIVE"
	FindingTakeoverPossible FindingType = "TAKEOVER_POSSIBLE"
	FindingTakeoverVerified FindingType = "TAKEOVER_VERIFIED"

	// TXT/Email record findings (contribute to takeover risk)
	FindingTXTDangling  FindingType = "TXT_DANGLING"  // Orphaned verification token
	FindingDMARCMissing FindingType = "DMARC_MISSING" // No DMARC — email spoofing possible
	FindingDMARCWeak    FindingType = "DMARC_WEAK"    // p=none — no enforcement
	FindingSPFMissing   FindingType = "SPF_MISSING"   // No SPF record
	FindingSPFWeak      FindingType = "SPF_WEAK"      // SPF allows any (+all / ~all)
)

// IsTakeover returns true if this finding represents a confirmed or likely takeover opportunity.
func (f *Finding) IsTakeover() bool {
	return f.Type == FindingTakeoverPossible || f.Type == FindingTakeoverVerified
}

// ScanResult is the aggregate result of a full scan run.
type ScanResult struct {
	Target    string // Root target (domain or label for list scans)
	StartedAt time.Time
	Duration  time.Duration
	Findings  []*Finding
	Errors    []ScanError
	Stats     ScanStats
}

// ScanStats holds counters for a scan run.
type ScanStats struct {
	DomainsScanned int
	DNSQueries     int
	HTTPRequests   int
	FindingsTotal  int
	Byseverity     map[Severity]int
}

// ScanError represents a non-fatal error encountered during scanning.
type ScanError struct {
	Domain  string
	Stage   string
	Message string
}
