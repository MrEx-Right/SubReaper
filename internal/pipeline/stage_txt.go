package pipeline

import (
	"context"
	"fmt"
	"strings"

	"github.com/MrEx-Right/SubReaper/internal/models"
	"github.com/MrEx-Right/SubReaper/internal/resolver"
)

// stageTXT performs analysis of TXT, SPF, and DMARC records for a registrable
// domain. The pipeline runs it once per registrable domain, never per subdomain,
// because subdomains normally inherit the parent's email policy through DMARC
// and rarely publish SPF of their own.
//
// It returns nothing when the domain does not exist or the lookup fails, so a
// resolver error can never be mistaken for a missing record.
func stageTXT(ctx context.Context, domain string, res *resolver.Resolver) ([]models.TXTRecord, []emailIssue) {
	rawRecords, err := res.ResolveTXT(ctx, domain)
	if err != nil {
		return nil, nil // includes resolver.ErrNXDOMAIN
	}

	var analysed []models.TXTRecord
	var issues []emailIssue

	hasSPF := false
	hasDMARC := false
	var services []string

	for _, raw := range rawRecords {
		rec := analyseTXTRecord(raw, domain)
		analysed = append(analysed, rec)

		switch rec.Kind {
		case "spf":
			hasSPF = true
			if rec.Issue != "" {
				issues = append(issues, emailIssue{
					findingType: models.FindingSPFWeak,
					severity:    spfSeverity(rec.Raw),
					description: rec.Issue,
					remediation: "Tighten SPF policy: replace ~all or +all with -all (hard fail).",
				})
			}
		case "dmarc":
			hasDMARC = true
			if rec.Issue != "" {
				issues = append(issues, emailIssue{
					findingType: models.FindingDMARCWeak,
					severity:    models.SeverityLow,
					description: rec.Issue,
					remediation: "Set DMARC policy to p=quarantine or p=reject to prevent email spoofing.",
				})
			}
		case "verification":
			if rec.Domain != "" {
				services = append(services, rec.Domain)
			}
		}
	}

	// Verification tokens are normal; they only matter if a service is no
	// longer used, which DNS alone cannot tell. Report them once, for review.
	if len(services) > 0 {
		issues = append(issues, emailIssue{
			findingType: models.FindingTXTDangling,
			severity:    models.SeverityInfo,
			description: fmt.Sprintf("%d domain verification token(s) present (%s). Review whether each service is still in use.",
				len(services), strings.Join(uniqueStrings(services), ", ")),
			remediation: "Remove verification TXT records for services that are no longer in use.",
		})
	}

	// Missing SPF — anyone can send mail claiming to be this domain
	if !hasSPF {
		issues = append(issues, emailIssue{
			findingType: models.FindingSPFMissing,
			severity:    models.SeverityLow,
			description: "No SPF record found for " + domain + ". Without SPF, anyone can send email appearing to be from this domain.",
			remediation: "Add an SPF TXT record (e.g. \"v=spf1 include:_spf.yourmailprovider.com -all\") to prevent email spoofing.",
		})
	}

	// Missing DMARC — no enforcement even if SPF/DKIM pass
	if !hasDMARC {
		issues = append(issues, emailIssue{
			findingType: models.FindingDMARCMissing,
			severity:    models.SeverityLow,
			description: "No DMARC record found at _dmarc." + domain + ". Without DMARC, SPF/DKIM failures result in no enforcement action.",
			remediation: "Add a DMARC TXT record at _dmarc." + domain + " with p=quarantine or p=reject.",
		})
	}

	return analysed, issues
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// spfSeverity grades a weak SPF policy: +all allows anyone, ?all is neutral,
// ~all (softfail) is common and safe together with an enforcing DMARC policy.
func spfSeverity(spf string) models.Severity {
	lower := strings.ToLower(spf)
	switch {
	case strings.Contains(lower, "+all"):
		return models.SeverityHigh
	case strings.Contains(lower, "?all"):
		return models.SeverityLow
	default:
		return models.SeverityInfo
	}
}

// emailIssue represents a TXT/email-level security problem.
type emailIssue struct {
	findingType models.FindingType
	severity    models.Severity
	description string
	remediation string
}

// analyseTXTRecord classifies and inspects a single raw TXT value.
func analyseTXTRecord(raw, domain string) models.TXTRecord {
	lower := strings.ToLower(raw)

	rec := models.TXTRecord{Raw: raw}

	switch {
	// ── DMARC (prefixed by ResolveTXT with "dmarc:") ─────────────────────
	case strings.HasPrefix(raw, "dmarc:"):
		actual := raw[len("dmarc:"):]
		rec.Raw = actual
		rec.Kind = "dmarc"
		rec.Issue = analyseDMARC(actual)

	// ── SPF ──────────────────────────────────────────────────────────────
	case strings.HasPrefix(lower, "v=spf1"):
		rec.Kind = "spf"
		rec.Issue = analyseSPF(lower)

	// ── DKIM (selector._domainkey.domain) ────────────────────────────────
	case strings.Contains(lower, "v=dkim1"):
		rec.Kind = "dkim"

	// ── Ownership/verification tokens ────────────────────────────────────
	case strings.HasPrefix(lower, "google-site-verification="):
		rec.Kind = "verification"
		token := strings.TrimPrefix(raw, "google-site-verification=")
		rec.Domain = "Google Search Console"
		rec.Issue = checkOrphanedToken("Google Search Console", token)

	case strings.HasPrefix(lower, "facebook-domain-verification="):
		rec.Kind = "verification"
		rec.Domain = "Facebook"
		rec.Issue = "Facebook domain verification token present. Review whether the service is still in use."

	case strings.HasPrefix(lower, "amazonses:"):
		rec.Kind = "verification"
		rec.Domain = "Amazon SES"
		rec.Issue = "Amazon SES verification token present. If SES is no longer configured, remove this record."

	case strings.HasPrefix(lower, "ms="):
		rec.Kind = "verification"
		rec.Domain = "Microsoft 365"
		rec.Issue = "Microsoft 365 domain verification token present. Review whether the service is still in use."

	case strings.HasPrefix(lower, "atlassian-domain-verification="):
		rec.Kind = "verification"
		rec.Domain = "Atlassian"
		rec.Issue = "Atlassian domain verification token present. Review whether the service is still in use."

	case strings.HasPrefix(lower, "cisco-ci-domain-verification="):
		rec.Kind = "verification"
		rec.Domain = "Cisco"
		rec.Issue = "Cisco domain verification token present. Review whether the service is still in use."

	case strings.HasPrefix(lower, "docusign="):
		rec.Kind = "verification"
		rec.Domain = "DocuSign"
		rec.Issue = "DocuSign domain verification token present. Review whether the service is still in use."

	case strings.HasPrefix(lower, "stripe-verification="):
		rec.Kind = "verification"
		rec.Domain = "Stripe"
		rec.Issue = "Stripe domain verification token present. Review whether the service is still in use."

	case strings.HasPrefix(lower, "have-i-been-pwned-verification="):
		rec.Kind = "verification"
		rec.Domain = "HaveIBeenPwned"

	default:
		rec.Kind = "unknown"
	}

	return rec
}

// analyseSPF checks whether an SPF record has a permissive policy.
func analyseSPF(spf string) string {
	if strings.Contains(spf, "+all") {
		return "SPF record uses +all (pass all), which allows any server to send email as this domain. This is effectively no protection."
	}
	if strings.Contains(spf, "~all") {
		return "SPF record uses ~all (softfail), which allows spoofed emails to be delivered with a spam flag. Upgrade to -all (hard fail)."
	}
	// ?all means neutral — also weak
	if strings.Contains(spf, "?all") {
		return "SPF record uses ?all (neutral), which provides no real protection against spoofing."
	}
	return "" // -all or no all → fine
}

// analyseDMARC checks whether a DMARC record enforces action.
func analyseDMARC(dmarc string) string {
	lower := strings.ToLower(dmarc)
	if strings.Contains(lower, "p=none") {
		return "DMARC policy is p=none (monitor only). No enforcement action is taken on failing messages. Upgrade to p=quarantine or p=reject."
	}
	return ""
}

// checkOrphanedToken describes a verification token for review. DNS alone
// cannot tell whether the service is still in use.
func checkOrphanedToken(service, _ string) string {
	return service + " domain verification token present. Review whether the service is still in use."
}
