package pipeline

import (
	"context"
	"strings"

	"github.com/MrEx-Right/SubReaper/internal/models"
	"github.com/MrEx-Right/SubReaper/internal/resolver"
)

// stageTXT performs analysis of TXT, SPF, and DMARC records for the root domain.
//
// Unlike other stages, this stage always runs (not gated by dangling DNS) because
// missing or misconfigured email protection records are a direct takeover enabler:
//   - A dangling MX record + no SPF/DMARC = trivial email spoofing
//   - Orphaned verification tokens (Google/Amazon/Facebook) may be re-claimable
//
// The stage returns an additional Finding only when a TXT-level issue is discovered
// independently of CNAME/NS/MX dangles. It also annotates an existing finding with
// TXTRecords so they appear in reports.
func stageTXT(ctx context.Context, domain string, res *resolver.Resolver) ([]models.TXTRecord, []emailIssue) {
	rawRecords, err := res.ResolveTXT(ctx, domain)
	if err != nil {
		return nil, nil
	}

	var analysed []models.TXTRecord
	var issues []emailIssue

	hasSPF := false
	hasDMARC := false

	for _, raw := range rawRecords {
		rec := analyseTXTRecord(raw, domain)
		analysed = append(analysed, rec)

		switch rec.Kind {
		case "spf":
			hasSPF = true
			if rec.Issue != "" {
				issues = append(issues, emailIssue{
					findingType: models.FindingSPFWeak,
					severity:    models.SeverityMedium,
					description: rec.Issue,
					remediation: "Tighten SPF policy: replace ~all or +all with -all (hard fail).",
				})
			}
		case "dmarc":
			hasDMARC = true
			if rec.Issue != "" {
				issues = append(issues, emailIssue{
					findingType: models.FindingDMARCWeak,
					severity:    models.SeverityMedium,
					description: rec.Issue,
					remediation: "Set DMARC policy to p=quarantine or p=reject to prevent email spoofing.",
				})
			}
		case "verification":
			if rec.Issue != "" {
				// Orphaned ownership token — could be re-claimed
				issues = append(issues, emailIssue{
					findingType: models.FindingTXTDangling,
					severity:    models.SeverityHigh,
					description: rec.Issue,
					remediation: "Remove the orphaned domain verification TXT record. It may allow an attacker to claim ownership of this domain in a third-party service.",
				})
			}
		}
	}

	// Missing SPF — contributes to email takeover risk (especially if MX is also dangling)
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
		rec.Issue = "Potential orphaned Facebook domain verification token. Verify this token is still actively used."

	case strings.HasPrefix(lower, "amazonses:"):
		rec.Kind = "verification"
		rec.Domain = "Amazon SES"
		rec.Issue = "Potential orphaned Amazon SES verification token. If SES is no longer configured, remove this record."

	case strings.HasPrefix(lower, "ms="):
		rec.Kind = "verification"
		rec.Domain = "Microsoft 365"
		rec.Issue = "Potential orphaned Microsoft 365 domain verification token. Verify this token is still actively used."

	case strings.HasPrefix(lower, "atlassian-domain-verification="):
		rec.Kind = "verification"
		rec.Domain = "Atlassian"
		rec.Issue = "Potential orphaned Atlassian domain verification token."

	case strings.HasPrefix(lower, "cisco-ci-domain-verification="):
		rec.Kind = "verification"
		rec.Domain = "Cisco"
		rec.Issue = "Potential orphaned Cisco domain verification token."

	case strings.HasPrefix(lower, "docusign="):
		rec.Kind = "verification"
		rec.Domain = "DocuSign"
		rec.Issue = "Potential orphaned DocuSign domain verification token."

	case strings.HasPrefix(lower, "stripe-verification="):
		rec.Kind = "verification"
		rec.Domain = "Stripe"
		rec.Issue = "Potential orphaned Stripe domain verification token."

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

// checkOrphanedToken is a placeholder for future active verification.
// Currently flags all verification tokens as potentially orphaned since
// we cannot verify ownership without the service's API.
func checkOrphanedToken(service, _ string) string {
	return "Potential orphaned " + service + " domain verification token. If this service is no longer in use, remove the record — it could allow an attacker to claim ownership."
}
