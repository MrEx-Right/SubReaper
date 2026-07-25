package pipeline

import (
	"context"
	"strings"

	"github.com/MrEx-Right/SubReaper/internal/models"
	"github.com/MrEx-Right/SubReaper/internal/providers"
)

// stageVerify performs Stage 4 of the pipeline: claim-state verification.
//
// For provider-identified findings, it runs the provider's ClaimCheck function
// to actively verify whether the resource is available to claim. This is the
// most definitive signal — a successful claim check upgrades the finding to
// CRITICAL / TAKEOVER_VERIFIED.
//
// Returns true if the resource was confirmed claimable.
func stageVerify(
	ctx context.Context,
	chain *models.DNSChain,
	match *models.ProviderMatch,
	registry *providers.Registry,
) (bool, error) {
	if match == nil || !match.IsIdentified() {
		return false, nil
	}

	// Find the provider in the registry
	var provider *providers.Provider
	for _, p := range registry.All() {
		if strings.EqualFold(p.Name, match.ProviderName) {
			provider = p
			break
		}
	}

	if provider == nil || provider.ClaimCheck == nil {
		// No claim check available for this provider
		return false, nil
	}

	// Determine the CNAME to check
	cname := ""
	if chain != nil {
		cname = chain.FinalCNAME()
		if cname == "" && chain.DanglingHop() != nil {
			cname = chain.DanglingHop().Value
		}
	}
	if cname == "" {
		return false, nil
	}

	// Run the provider-specific claim check
	claimable, err := provider.ClaimCheck(ctx, cname)
	if err != nil {
		return false, err
	}

	if claimable {
		// Add a verified signal to the match
		match.Signals = append(match.Signals, models.Signal{
			Type:        models.SignalClaimVerified,
			Description: "Claim check confirmed: resource is unclaimed",
			Points:      0, // doesn't affect score; it's a binary confirmation
		})
	}

	return claimable, nil
}
