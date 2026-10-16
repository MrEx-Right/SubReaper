// Package pipeline implements the multi-stage verification pipeline that
// SubReaper runs against each target domain.
//
// Stage 1 (DNS)  → Stage 2 (HTTP) → Stage 3 (Fingerprint) → Stage 4 (Verify)
//
// A domain reaches the HTTP and fingerprint stages when its CNAME chain is
// dangling (a CNAME target returns NXDOMAIN) or when any CNAME in the chain
// points at a known provider. The second case covers takeovers where the
// provider's DNS still resolves and only the HTTP response shows that the
// resource is unclaimed (GitHub Pages, S3, Heroku, Shopify, ...).
package pipeline

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/MrEx-Right/SubReaper/internal/config"
	"github.com/MrEx-Right/SubReaper/internal/models"
	"github.com/MrEx-Right/SubReaper/internal/providers"
	"github.com/MrEx-Right/SubReaper/internal/ratelimit"
	"github.com/MrEx-Right/SubReaper/internal/resolver"
	"golang.org/x/net/publicsuffix"
)

// Pipeline orchestrates the four-stage verification process for a single domain.
// It is safe for concurrent use.
type Pipeline struct {
	cfg      *config.Config
	resolver *resolver.Resolver
	registry *providers.Registry
	limiter  *ratelimit.Limiter
	checkEnv *providers.CheckEnv

	wildcards  sync.Map // parent domain -> *wildcardEntry
	reportedWC sync.Map // "*.parent" -> struct{}, wildcard findings already emitted
	emailDone  sync.Map // registrable domain -> struct{}, email checks already run
}

type wildcardEntry struct {
	once sync.Once
	sig  string
}

// New creates a Pipeline with the given configuration, resolver, and provider registry.
func New(cfg *config.Config, res *resolver.Resolver, reg *providers.Registry) *Pipeline {
	p := &Pipeline{
		cfg:      cfg,
		resolver: res,
		registry: reg,
	}
	p.checkEnv = &providers.CheckEnv{
		IsNXDOMAIN: res.IsNXDOMAIN,
		HTTP:       providers.DefaultHTTPClient(cfg.Timeout),
	}
	return p
}

// SetLimiter applies a request rate limit to the HTTP probes.
func (p *Pipeline) SetLimiter(l *ratelimit.Limiter) { p.limiter = l }

// Run executes the full verification pipeline for the given domain.
// It returns the findings for the domain (possibly none). Email-policy
// findings for the domain's registrable domain are returned only by the
// first Run that touches that registrable domain.
func (p *Pipeline) Run(ctx context.Context, domain string) ([]*models.Finding, error) {
	started := time.Now()
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))

	chain, findingType, err := p.stageDNS(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("dns stage: %w", err)
	}
	if chain.NotExist {
		// The name has no records at all: nothing can dangle and there is
		// no email configuration to analyse.
		return nil, nil
	}

	var findings []*models.Finding
	if f := p.analyseChain(ctx, domain, chain, findingType, started); f != nil {
		findings = append(findings, f)
	}
	findings = append(findings, p.emailFindings(ctx, domain, started)...)
	return findings, nil
}

// analyseChain runs stages 2–4 for a domain whose DNS chain is known.
func (p *Pipeline) analyseChain(ctx context.Context, domain string, chain *models.DNSChain, findingType models.FindingType, started time.Time) *models.Finding {
	dangling := chain.IsDangling()
	providerCNAME := p.registry.MatchAnyCNAME(chain.CNAMETargets())
	if !dangling && !providerCNAME {
		return nil // healthy, and nothing points at a known provider
	}

	subdomain := domain
	if chain.IsWildcard {
		// Every name under the parent is answered by the same wildcard
		// record; report it once as the wildcard itself.
		subdomain = "*." + parentDomain(domain)
		if _, dup := p.reportedWC.LoadOrStore(subdomain, struct{}{}); dup {
			return nil
		}
	}

	finding := &models.Finding{
		Target:       domain,
		Subdomain:    subdomain,
		Type:         findingType,
		Chain:        chain,
		Severity:     models.SeverityLow,
		DiscoveredAt: started,
	}
	if !dangling {
		finding.Type = models.FindingCNAMEDangling
	}
	switch finding.Type {
	case models.FindingNSDangling:
		finding.Severity = models.SeverityMedium
	case models.FindingMXDangling:
		finding.Severity = models.SeverityLow
	}

	if ips, _ := p.resolver.ResolveIPs(ctx, domain); len(ips) > 0 {
		finding.IPs = ips
	}

	// ── Stage 2: HTTP Probing ────────────────────────────────────────────────
	if !p.cfg.NoHTTP && finding.Type != models.FindingMXDangling && finding.Type != models.FindingNSDangling {
		finding.HTTPProbes = stageHTTP(ctx, domain, chain, p.cfg, p.limiter)
	}

	// ── Stage 2.5: Technology Fingerprinting (optional) ──────────────────────
	if p.cfg.TechDetect && len(finding.HTTPProbes) > 0 {
		finding.Technologies = stageTech(finding.HTTPProbes)
	}

	// ── Stage 3: Provider Fingerprinting ─────────────────────────────────────
	match := stageFingerprint(chain, finding.HTTPProbes, p.registry)
	finding.Provider = match

	confirmed := match.IsIdentified() && match.HasEvidence()
	if !dangling && !confirmed {
		// The CNAME points at a provider, but nothing shows the resource
		// is unclaimed: this is a normal, working deployment.
		return nil
	}

	if confirmed {
		switch {
		case match.Status == models.StatusNotVulnerable:
			// The provider is identified but does not allow claiming the
			// name; keep the dangling record as informational.
			finding.Severity = models.SeverityInfo
		case match.Confidence >= 80:
			finding.Severity = models.SeverityHigh
			finding.Type = models.FindingTakeoverPossible
		default:
			finding.Severity = models.SeverityMedium
			finding.Type = models.FindingTakeoverPossible
		}
	}

	// ── Stage 4: Claim-State Verification ────────────────────────────────────
	if confirmed && match.Status != models.StatusNotVulnerable && !p.cfg.NoVerify && !p.cfg.ResearchMode {
		verified, err := stageVerify(ctx, chain, match, p.registry, p.checkEnv)
		if err == nil && verified {
			match.ClaimVerified = true
			finding.Severity = models.SeverityCritical
			finding.Type = models.FindingTakeoverVerified
		}
	}

	finding.Description = buildDescription(finding)
	finding.Remediation = buildRemediation(finding)
	return finding
}

// emailFindings runs the TXT/SPF/DMARC checks once per registrable domain.
func (p *Pipeline) emailFindings(ctx context.Context, domain string, started time.Time) []*models.Finding {
	root := rootDomain(domain)
	if root == "" {
		return nil
	}
	if _, done := p.emailDone.LoadOrStore(root, struct{}{}); done {
		return nil
	}

	txtRecords, issues := stageTXT(ctx, root, p.resolver)
	var out []*models.Finding
	for _, iss := range issues {
		out = append(out, &models.Finding{
			Target:       root,
			Subdomain:    root,
			Type:         iss.findingType,
			Severity:     iss.severity,
			TXTRecords:   txtRecords,
			Description:  iss.description,
			Remediation:  iss.remediation,
			DiscoveredAt: started,
		})
	}
	return out
}

// rootDomain returns the registrable domain (eTLD+1) of domain, using the
// public suffix list: "api.example.co.uk" → "example.co.uk".
// It returns "" when domain is itself a public suffix.
func rootDomain(domain string) string {
	root, err := publicsuffix.EffectiveTLDPlusOne(strings.TrimSuffix(domain, "."))
	if err != nil {
		return ""
	}
	return root
}

// parentDomain strips the leftmost label: "a.b.example.com" → "b.example.com".
func parentDomain(domain string) string {
	if i := strings.IndexByte(domain, '.'); i >= 0 {
		return domain[i+1:]
	}
	return ""
}

// buildDescription generates a concise human-readable summary of a finding.
func buildDescription(f *models.Finding) string {
	chain := f.Chain
	if chain == nil {
		return "Dangling DNS record detected."
	}

	prefix := ""
	if chain.IsWildcard {
		prefix = "Wildcard record: every name under " + strings.TrimPrefix(f.Subdomain, "*.") + " is affected. "
	}

	switch f.Type {
	case models.FindingNSDangling, models.FindingMXDangling:
		if h := chain.DanglingHop(); h != nil {
			return fmt.Sprintf("%s%s record of %s points to %s, which returns NXDOMAIN. If that domain can be registered, an attacker controls it.",
				prefix, h.RecordType, f.Target, h.Value)
		}
	}

	target := chain.FinalCNAME()
	if f.Provider != nil && f.Provider.IsIdentified() && f.Provider.HasEvidence() {
		var note string
		switch f.Provider.Status {
		case models.StatusNotVulnerable:
			note = " This provider is not known to allow claiming the name, so the record is reported for cleanup only."
		case models.StatusEdgeCase:
			note = " Takeover on this provider works only in some configurations; confirm manually."
		}
		if chain.IsDangling() {
			return fmt.Sprintf("%sCNAME points to %s (%s), which returns NXDOMAIN.%s", prefix, target, f.Provider.ProviderName, note)
		}
		return fmt.Sprintf("%sCNAME points to %s (%s) and the response matches the provider's unclaimed-resource page.%s",
			prefix, target, f.Provider.ProviderName, note)
	}

	if target == "" {
		if h := chain.DanglingHop(); h != nil {
			target = h.Name
		}
	}
	return fmt.Sprintf("%sCNAME chain for %s ends at %s, which returns NXDOMAIN. Provider unknown.", prefix, f.Target, target)
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
