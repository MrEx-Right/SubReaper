package pipeline

import (
	"net"
	"strings"

	"github.com/MrEx-Right/SubReaper/internal/models"
	"github.com/MrEx-Right/SubReaper/internal/providers"
)

// Signal point values — must match the plan's confidence scoring table.
const (
	pointsCNAMESuffix = 40
	pointsIPRange     = 30
	pointsTLSCert     = 25
	pointsHeader      = 20
	pointsBodyMarker  = 10
	pointsStatusCode  = 5
)

// stageFingerprint performs Stage 3 of the pipeline: multi-signal provider
// fingerprinting.
//
// It evaluates every registered provider against the DNS chain and HTTP probe
// results, building a confidence score from multiple independent signals.
// A provider is only considered identified if its score reaches ≥60 AND at
// least two independent signal types contributed.
//
// Returns the best-matching ProviderMatch (which may be unidentified if no
// provider reaches the threshold).
func stageFingerprint(
	chain *models.DNSChain,
	probes []*models.HTTPProbe,
	registry *providers.Registry,
) *models.ProviderMatch {
	// Extract evidence from the DNS chain
	finalCNAME := ""
	if chain != nil {
		finalCNAME = chain.FinalCNAME()
		if finalCNAME == "" && chain.DanglingHop() != nil {
			finalCNAME = chain.DanglingHop().Value
		}
	}

	// Parse IPs from probes (from headers like X-Served-By etc.)
	resolvedIPs := extractIPs(probes)

	bestMatch := &models.ProviderMatch{}

	for _, p := range registry.All() {
		var signals []models.Signal

		// ── Signal 1: CNAME suffix ────────────────────────────────────────────
		if finalCNAME != "" {
			if matched := p.MatchCNAME(finalCNAME); matched != "" {
				signals = append(signals, models.Signal{
					Type:        models.SignalCNAMESuffix,
					Description: "CNAME suffix matches: " + matched,
					Points:      pointsCNAMESuffix,
				})
			}
		}

		// ── Signal 2: IP range ────────────────────────────────────────────────
		for _, ip := range resolvedIPs {
			if p.MatchIP(ip) {
				signals = append(signals, models.Signal{
					Type:        models.SignalIPRange,
					Description: "IP " + ip.String() + " is in provider range",
					Points:      pointsIPRange,
				})
				break // one IP match is sufficient
			}
		}

		// ── Signals 3–5: HTTP probe evidence ─────────────────────────────────
		for _, probe := range probes {
			if probe == nil || probe.Error != "" {
				continue
			}

			// TLS certificate subject/issuer
			for _, certToken := range p.TLSCertContains {
				if strings.Contains(strings.ToLower(probe.TLSSubject), strings.ToLower(certToken)) ||
					strings.Contains(strings.ToLower(probe.TLSIssuer), strings.ToLower(certToken)) {
					signals = append(signals, models.Signal{
						Type:        models.SignalTLSCert,
						Description: "TLS cert contains: " + certToken,
						Points:      pointsTLSCert,
					})
					break
				}
			}

			// Response headers
			if matched := p.MatchHeader(probe.Headers); len(matched) > 0 {
				for _, m := range matched {
					signals = append(signals, models.Signal{
						Type:        models.SignalHeader,
						Description: "Header: " + m,
						Points:      pointsHeader,
					})
				}
			}

			// Status code (weak signal — 404 alone is not meaningful)
			if probe.StatusCode == 404 {
				signals = append(signals, models.Signal{
					Type:        models.SignalStatusCode,
					Description: "HTTP 404",
					Points:      pointsStatusCode,
				})
			}

			// Body signals (weakest — last resort)
			if matched := p.MatchBody(probe.BodyString()); len(matched) > 0 {
				for _, m := range matched {
					signals = append(signals, models.Signal{
						Type:        models.SignalBodyMarker,
						Description: "Body contains: " + m,
						Points:      pointsBodyMarker,
					})
				}
			}
		}

		if len(signals) == 0 {
			continue
		}

		// Require at least two distinct signal types for a confident match
		distinctTypes := countDistinctSignalTypes(signals)
		score := p.Score(signals)

		if score >= 60 && distinctTypes >= 2 {
			if score > bestMatch.Confidence {
				bestMatch = &models.ProviderMatch{
					ProviderName:    p.Name,
					Confidence:      score,
					Signals:         signals,
					ClaimVerified:   false,
					TakeoverWriteup: p.TakeoverDoc,
					ClaimURL:        p.ClaimURL,
				}
			}
		} else if score > 0 && score > bestMatch.Confidence && !bestMatch.IsIdentified() {
			// Partial match — better than nothing, but not yet "identified"
			bestMatch = &models.ProviderMatch{
				ProviderName:    p.Name,
				Confidence:      score,
				Signals:         signals,
				TakeoverWriteup: p.TakeoverDoc,
				ClaimURL:        p.ClaimURL,
			}
		}
	}

	return bestMatch
}

// countDistinctSignalTypes returns the number of distinct SignalType values
// in a signal slice.
func countDistinctSignalTypes(signals []models.Signal) int {
	seen := make(map[models.SignalType]struct{})
	for _, s := range signals {
		seen[s.Type] = struct{}{}
	}
	return len(seen)
}

// extractIPs parses IP addresses from probe response headers and bodies.
// We look at the IP that was actually connected to (from the transport level
// if available) as well as common proxy headers.
func extractIPs(probes []*models.HTTPProbe) []net.IP {
	var ips []net.IP
	seen := make(map[string]bool)

	for _, probe := range probes {
		if probe == nil {
			continue
		}
		// X-Served-By, X-Cache (Fastly etc.) often contain hostnames/IPs
		for _, h := range []string{"x-served-by", "x-real-ip", "x-forwarded-for"} {
			val := probe.Header(h)
			if val == "" {
				continue
			}
			// May be comma-separated
			for _, part := range strings.Split(val, ",") {
				part = strings.TrimSpace(part)
				if ip := net.ParseIP(part); ip != nil && !seen[ip.String()] {
					seen[ip.String()] = true
					ips = append(ips, ip)
				}
			}
		}
	}
	return ips
}
