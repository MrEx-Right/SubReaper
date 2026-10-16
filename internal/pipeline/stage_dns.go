package pipeline

import (
	"context"

	"github.com/MrEx-Right/SubReaper/internal/models"
	"github.com/MrEx-Right/SubReaper/internal/resolver"
)

// stageDNS performs Stage 1 of the pipeline: full DNS chain traversal.
//
// It traverses the CNAME chain for the domain and also checks NS and MX records
// for dangling pointers. NS and MX records only count as dangling when their
// target returns NXDOMAIN; a timeout or SERVFAIL is not evidence.
//
// Returns the DNS chain, the finding type if dangling, and any error.
func (p *Pipeline) stageDNS(ctx context.Context, domain string) (*models.DNSChain, models.FindingType, error) {
	chain, err := p.resolver.TraverseChain(ctx, domain)
	if err != nil {
		return nil, "", err
	}
	if chain.NotExist {
		return chain, "", nil
	}

	// A name answered by its parent's wildcard record is not a record of its
	// own. It is still analysed, but reported once as "*.parent".
	if sig := p.wildcardSignature(ctx, domain); sig != "" && sig == resolver.ChainSignature(chain) {
		chain.IsWildcard = true
	}

	if chain.IsDangling() {
		return chain, models.FindingCNAMEDangling, nil
	}
	if chain.IsWildcard || len(chain.CNAMETargets()) > 0 {
		// NS/MX records cannot coexist with a CNAME, and wildcard answers
		// carry no NS/MX of their own.
		return chain, "", nil
	}

	nsHops, err := p.resolver.ResolveNS(ctx, domain)
	if err == nil {
		for _, hop := range nsHops {
			if hop.NXDOMAIN {
				return &models.DNSChain{
					Root:          domain,
					Hops:          []models.DNSHop{hop},
					DanglingPoint: 0,
				}, models.FindingNSDangling, nil
			}
		}
	}

	mxHops, err := p.resolver.ResolveMX(ctx, domain)
	if err == nil {
		for _, hop := range mxHops {
			if hop.NXDOMAIN {
				return &models.DNSChain{
					Root:          domain,
					Hops:          []models.DNSHop{hop},
					DanglingPoint: 0,
				}, models.FindingMXDangling, nil
			}
		}
	}

	return chain, "", nil
}

// wildcardSignature returns the cached wildcard signature of domain's parent,
// probing it on first use. Registrable domains and public suffixes are never
// probed, since their parent is a TLD.
func (p *Pipeline) wildcardSignature(ctx context.Context, domain string) string {
	root := rootDomain(domain)
	if root == "" || root == domain {
		return ""
	}
	parent := parentDomain(domain)
	v, _ := p.wildcards.LoadOrStore(parent, &wildcardEntry{})
	entry := v.(*wildcardEntry)
	entry.once.Do(func() {
		sig, err := p.resolver.WildcardSignature(ctx, parent)
		if err == nil {
			entry.sig = sig
		}
	})
	return entry.sig
}
