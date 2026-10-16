package pipeline

import (
	"net"
	"strings"

	"github.com/MrEx-Right/SubReaper/internal/models"
	"github.com/MrEx-Right/SubReaper/internal/providers"
)

// Signal point values.
//
// A CNAME into the provider identifies it; an NXDOMAIN target or an
// unclaimed-resource body marker is the evidence that the name is free.
// CNAME + evidence (≥ 65) is enough to identify a takeover candidate;
// a matching provider header on top of that raises it past 80 (HIGH).
const (
	pointsCNAMESuffix = 40
	pointsNXDomain    = 40
	pointsIPRange     = 30
	pointsTLSCert     = 25
	pointsBodyMarker  = 25
	pointsHeader      = 20
	pointsStatusCode  = 5
)

// stageFingerprint performs Stage 3 of the pipeline: multi-signal provider
// fingerprinting.
//
// It evaluates every registered provider against the DNS chain and HTTP probe
// results, building a confidence score from multiple independent signals.
// A provider is only considered identified if its score reaches ≥60 AND at
// least two independent signal types contributed. Only providers whose CNAME
// suffix appears in the chain are considered, so headers or body text alone
// can never produce a match.
//
// Returns the best-matching ProviderMatch (which may be unidentified if no
// provider reaches the threshold).
func stageFingerprint(
	chain *models.DNSChain,
	probes []*models.HTTPProbe,
	registry *providers.Registry,
) *models.ProviderMatch {
	var cnames []string
	nxTarget := false
	if chain != nil {
		cnames = chain.CNAMETargets()
		if h := chain.DanglingHop(); h != nil && h.NXDOMAIN && h.RecordType == models.RecordCNAME && len(cnames) > 0 {
			nxTarget = true
		}
	}

	resolvedIPs := extractIPs(probes)
	bestMatch := &models.ProviderMatch{}

	for _, p := range registry.All() {
		// ── Signal 1: CNAME suffix (required) ────────────────────────────────
		matchedSuffix, matchedCNAME := "", ""
		for i := len(cnames) - 1; i >= 0; i-- {
			if m := p.MatchCNAME(cnames[i]); m != "" {
				matchedSuffix, matchedCNAME = m, cnames[i]
				break
			}
		}
		if matchedSuffix == "" {
			continue
		}

		var signals []models.Signal
		seen := make(map[string]bool)
		add := func(s models.Signal) {
			key := string(s.Type) + "|" + s.Description
			if s.Type == models.SignalHeader {
				// Count each header name once, whatever its value per probe.
				key = string(s.Type) + "|" + strings.ToLower(strings.SplitN(s.Description, ":", 3)[1])
			}
			if seen[key] {
				return
			}
			seen[key] = true
			signals = append(signals, s)
		}

		add(models.Signal{
			Type:        models.SignalCNAMESuffix,
			Description: "CNAME " + matchedCNAME + " matches " + matchedSuffix,
			Points:      pointsCNAMESuffix,
		})

		// ── Signal 2: NXDOMAIN at the provider target ────────────────────────
		if nxTarget && cnames[len(cnames)-1] == matchedCNAME {
			add(models.Signal{
				Type:        models.SignalDNSNXDomain,
				Description: matchedCNAME + " returns NXDOMAIN",
				Points:      pointsNXDomain,
			})
		}

		// ── Signal 3: IP range ───────────────────────────────────────────────
		for _, ip := range resolvedIPs {
			if p.MatchIP(ip) {
				add(models.Signal{
					Type:        models.SignalIPRange,
					Description: "IP " + ip.String() + " is in provider range",
					Points:      pointsIPRange,
				})
				break
			}
		}

		// ── Signals 4–7: HTTP probe evidence ─────────────────────────────────
		for _, probe := range probes {
			if probe == nil || probe.Error != "" {
				continue
			}

			for _, certToken := range p.TLSCertContains {
				if strings.Contains(strings.ToLower(probe.TLSSubject), strings.ToLower(certToken)) ||
					strings.Contains(strings.ToLower(probe.TLSIssuer), strings.ToLower(certToken)) {
					add(models.Signal{
						Type:        models.SignalTLSCert,
						Description: "TLS cert contains: " + certToken,
						Points:      pointsTLSCert,
					})
					break
				}
			}

			for _, m := range p.MatchHeader(probe.Headers) {
				add(models.Signal{
					Type:        models.SignalHeader,
					Description: "Header: " + m,
					Points:      pointsHeader,
				})
			}

			if probe.StatusCode == 404 {
				add(models.Signal{
					Type:        models.SignalStatusCode,
					Description: "HTTP 404",
					Points:      pointsStatusCode,
				})
			}

			for _, m := range p.MatchBody(probe.BodyString()) {
				add(models.Signal{
					Type:        models.SignalBodyMarker,
					Description: "Body contains: " + m,
					Points:      pointsBodyMarker,
				})
			}
		}

		score := p.Score(signals)
		candidate := &models.ProviderMatch{
			ProviderName:    p.Name,
			Confidence:      score,
			Signals:         signals,
			TakeoverWriteup: p.TakeoverDoc,
			ClaimURL:        p.ClaimURL,
			Status:          p.Status,
		}
		identified := score >= 60 && countDistinctSignalTypes(signals) >= 2
		if !identified {
			// Keep the confidence below the identification threshold so
			// IsIdentified stays false for partial matches.
			if candidate.Confidence >= 60 {
				candidate.Confidence = 59
			}
		}
		if better(candidate, bestMatch) {
			bestMatch = candidate
		}
	}

	return bestMatch
}

// better reports whether a should replace b as the best match: identified
// beats unidentified, evidence beats none, then higher confidence wins.
func better(a, b *models.ProviderMatch) bool {
	if a.IsIdentified() != b.IsIdentified() {
		return a.IsIdentified()
	}
	if a.HasEvidence() != b.HasEvidence() {
		return a.HasEvidence()
	}
	return a.Confidence > b.Confidence
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

// extractIPs parses IP addresses from common proxy headers in the probes.
func extractIPs(probes []*models.HTTPProbe) []net.IP {
	var ips []net.IP
	seen := make(map[string]bool)

	for _, probe := range probes {
		if probe == nil {
			continue
		}
		for _, h := range []string{"x-served-by", "x-real-ip", "x-forwarded-for"} {
			val := probe.Header(h)
			if val == "" {
				continue
			}
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
