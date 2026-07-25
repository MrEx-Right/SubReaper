package pipeline

import (
	"context"

	"github.com/MrEx-Right/SubReaper/internal/models"
	"github.com/MrEx-Right/SubReaper/internal/resolver"
)

// stageDNS performs Stage 1 of the pipeline: full DNS chain traversal.
//
// It traverses the CNAME chain for the domain and also checks NS and MX records
// for dangling pointers. The pipeline short-circuits here if no dangling point
// is found in any record type.
//
// Returns the DNS chain, the finding type if dangling, and any error.
func stageDNS(ctx context.Context, domain string, res *resolver.Resolver) (*models.DNSChain, models.FindingType, error) {
	// Check for wildcard DNS first — if wildcard is active, nothing is dangling
	isWildcard, err := res.CheckWildcard(ctx, domain)
	if err == nil && isWildcard {
		// Wildcard detected — report it but don't flag as dangling
		chain := &models.DNSChain{
			Root:          domain,
			DanglingPoint: -1,
			IsWildcard:    true,
		}
		return chain, "", nil
	}

	// Full CNAME chain traversal
	chain, err := res.TraverseChain(ctx, domain)
	if err != nil {
		return nil, "", err
	}
	chain.IsWildcard = isWildcard

	if chain.IsDangling() {
		// Determine finding type from the dangling hop's record type
		hop := chain.DanglingHop()
		if hop != nil && hop.RecordType == models.RecordA {
			return chain, models.FindingIPUnresponsive, nil
		}
		return chain, models.FindingCNAMEDangling, nil
	}

	// CNAME chain is clean — check NS records for dangling nameservers
	nsHops, err := res.ResolveNS(ctx, domain)
	if err == nil {
		for _, hop := range nsHops {
			if hop.NXDOMAIN || !hop.Resolved {
				// Build a synthetic chain representing the NS dangling
				nsChain := &models.DNSChain{
					Root:          domain,
					Hops:          []models.DNSHop{hop},
					DanglingPoint: 0,
				}
				return nsChain, models.FindingNSDangling, nil
			}
		}
	}

	// Check MX records for dangling mail exchangers
	mxHops, err := res.ResolveMX(ctx, domain)
	if err == nil {
		for _, hop := range mxHops {
			if hop.NXDOMAIN || !hop.Resolved {
				mxChain := &models.DNSChain{
					Root:          domain,
					Hops:          []models.DNSHop{hop},
					DanglingPoint: 0,
				}
				return mxChain, models.FindingMXDangling, nil
			}
		}
	}

	// No dangling point found anywhere
	return chain, "", nil
}
