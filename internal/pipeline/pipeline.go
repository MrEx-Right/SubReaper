// Package pipeline implements the multi-stage verification pipeline that
// SubReaper runs against each target domain.
//
// Stage 1 (DNS)  → Stage 2 (HTTP) → Stage 3 (Fingerprint) → Stage 4 (Verify)
//
// Each stage can short-circuit the pipeline. Results from earlier stages are
// passed to later stages to avoid redundant work.
package pipeline

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/MrEx-Right/SubReaper/internal/config"
	"github.com/MrEx-Right/SubReaper/internal/models"
	"github.com/MrEx-Right/SubReaper/internal/providers"
	"github.com/MrEx-Right/SubReaper/internal/resolver"
)

// Pipeline orchestrates the four-stage verification process for a single domain.
type Pipeline struct {
	cfg      *config.Config
	resolver *resolver.Resolver
	registry *providers.Registry
}

// New creates a Pipeline with the given configuration, resolver, and provider registry.
func New(cfg *config.Config, res *resolver.Resolver, reg *providers.Registry) *Pipeline {
	return &Pipeline{
		cfg:      cfg,
		resolver: res,
		registry: reg,
	}
}

// Run executes the full verification pipeline for the given domain.
// It returns a Finding if a vulnerability is detected, or nil if the domain
// appears healthy.
func (p *Pipeline) Run(ctx context.Context, domain string) (*models.Finding, error) {
	started := time.Now()

	// ── Stage 1: DNS Chain Analysis ──────────────────────────────────────────
	chain, findingType, err := stageDNS(ctx, domain, p.resolver)
	if err != nil {
		return nil, fmt.Errorf("dns stage: %w", err)
	}
	if chain == nil || !chain.IsDangling() {
		// No dangling CNAME/NS/MX — still run TXT analysis on root domain
		return p.runTXTOnly(ctx, domain, started)
	}

	finding := &models.Finding{
		Target:       domain,
		Subdomain:    domain,
		Type:         findingType,
		Chain:        chain,
		Severity:     models.SeverityLow, // will be upgraded in later stages
		DiscoveredAt: started,
	}

	// Resolve IPs for the finding record
	ips, _ := p.resolver.ResolveIPs(ctx, domain)
	finding.IPs = ips

	// ── Stage 2: HTTP Probing ─────────────────────────────────────────────────
	if !p.cfg.NoHTTP {
		probes, err := stageHTTP(ctx, domain, chain, p.cfg)
		if err == nil {
			finding.HTTPProbes = probes
		}
	}

	// ── Stage 2.5: Technology Fingerprinting (optional) ───────────────────────
	if p.cfg.TechDetect && len(finding.HTTPProbes) > 0 {
		finding.Technologies = stageTech(finding.HTTPProbes)
	}

	// ── Stage 3: Provider Fingerprinting ────────────────────────────────────
	match := stageFingerprint(chain, finding.HTTPProbes, p.registry)
	finding.Provider = match

	// Upgrade severity based on provider identification
	if match.IsIdentified() {
		if match.Confidence >= 80 {
			finding.Severity = models.SeverityHigh
			finding.Type = models.FindingTakeoverPossible
		} else {
			finding.Severity = models.SeverityMedium
			finding.Type = models.FindingTakeoverPossible
		}
	}

	// ── Stage 3.5: TXT / SPF / DMARC Analysis ────────────────────────────────
	// Extract root domain for TXT analysis (subdomains share the root's email config)
	txtDomain := rootDomain(domain)
	txtRecords, emailIssues := stageTXT(ctx, txtDomain, p.resolver)
	finding.TXTRecords = txtRecords

	// If MX is dangling AND there's no SPF/DMARC, elevate the severity
	if finding.Type == models.FindingMXDangling {
		for _, issue := range emailIssues {
			if issue.findingType == models.FindingSPFMissing || issue.findingType == models.FindingDMARCMissing {
				// Dangling MX + no email protection = HIGH risk
				if finding.Severity < models.SeverityHigh {
					finding.Severity = models.SeverityHigh
				}
			}
		}
	}

	// ── Stage 4: Claim-State Verification ────────────────────────────────────
	if !p.cfg.NoVerify && !p.cfg.ResearchMode && match.IsIdentified() {
		verified, err := stageVerify(ctx, chain, match, p.registry)
		if err == nil && verified {
			match.ClaimVerified = true
			finding.Severity = models.SeverityCritical
			finding.Type = models.FindingTakeoverVerified
		}
	}

	// Build human-readable description and remediation
	finding.Description = buildDescription(finding)
	finding.Remediation = buildRemediation(finding)

	return finding, nil
}

// runTXTOnly runs TXT/SPF/DMARC analysis when DNS chain is healthy.
// It only returns a finding when an issue is found.
func (p *Pipeline) runTXTOnly(ctx context.Context, domain string, started time.Time) (*models.Finding, error) {
	txtRecords, issues := stageTXT(ctx, domain, p.resolver)
	if len(issues) == 0 {
		return nil, nil
	}

	// Return the highest-severity TXT issue as the primary finding
	var worst emailIssue
	for _, iss := range issues {
		if iss.severity > worst.severity {
			worst = iss
		}
	}

	finding := &models.Finding{
		Target:       domain,
		Subdomain:    domain,
		Type:         worst.findingType,
		Severity:     worst.severity,
		TXTRecords:   txtRecords,
		Description:  worst.description,
		Remediation:  worst.remediation,
		DiscoveredAt: started,
	}

	return finding, nil
}

// rootDomain strips the leftmost label(s) to get the registrable domain.
// For "api.staging.example.com" it returns "example.com".
// This is a simple heuristic (splits on last two labels) — sufficient for TXT lookup.
func rootDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return domain
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// buildDescription generates a concise human-readable summary of a finding.
func buildDescription(f *models.Finding) string {
	chain := f.Chain
	if chain == nil {
		return "Dangling DNS record detected."
	}

	dangling := chain.DanglingHop()
	if dangling == nil {
		return "DNS chain analysis identified a potential dangling record."
	}

	if f.Provider != nil && f.Provider.IsIdentified() {
		return fmt.Sprintf(
			"CNAME chain points to %s (%s). The resource appears to be unclaimed and potentially takeable.",
			dangling.Value, f.Provider.ProviderName,
		)
	}

	return fmt.Sprintf(
		"DNS chain for %s ends at %s which returns %s. Provider unknown.",
		f.Target, dangling.Value, danglingStatus(dangling),
	)
}

// buildRemediation generates remediation advice based on finding type and provider.
func buildRemediation(f *models.Finding) string {
	switch f.Type {
	case models.FindingTakeoverVerified:
		return "URGENT: Remove the dangling CNAME record immediately. " +
			"If the service is still needed, recreate the resource before removing the DNS record."
	case models.FindingTakeoverPossible:
		return "Remove or update the CNAME record to point to an active resource. " +
			"Verify that the target service is correctly provisioned."
	case models.FindingNSDangling:
		return "Remove the NS delegation records for the dangling nameserver, " +
			"or re-register the nameserver domain."
	case models.FindingMXDangling:
		return "Remove or correct the MX record. " +
			"Dangling MX records can allow email interception."
	default:
		return "Remove the DNS record if the service is no longer in use."
	}
}

// danglingStatus returns a display string for the status of a dangling hop.
func danglingStatus(h *models.DNSHop) string {
	if h.NXDOMAIN {
		return "NXDOMAIN"
	}
	return "unresolved"
}
