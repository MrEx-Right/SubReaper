package pipeline

import (
	"strings"

	"github.com/MrEx-Right/SubReaper/internal/models"
)

// stageTech performs Stage 2.5: technology fingerprinting.
//
// It analyses HTTP probe results (headers + body) to identify the underlying
// technologies in use. This is a security-relevant step because certain
// technology stacks are more susceptible to subdomain takeover — for example,
// a dangling CNAME to a platform whose SDK is still loaded in the page body
// is strong confirmatory evidence of a takeover opportunity.
//
// The stage returns a list of detected technology names to be attached to the Finding.
func stageTech(probes []*models.HTTPProbe) []string {
	seen := make(map[string]struct{})
	var techs []string

	add := func(name string) {
		if _, ok := seen[name]; !ok {
			seen[name] = struct{}{}
			techs = append(techs, name)
		}
	}

	for _, probe := range probes {
		if probe == nil || probe.Error != "" {
			continue
		}
		detectFromHeaders(probe, add)
		detectFromBody(probe, add)
		detectFromTLS(probe, add)
	}

	return techs
}

type adder func(name string)

// ─── Header-based detection ───────────────────────────────────────────────────

func detectFromHeaders(probe *models.HTTPProbe, add adder) {
	server := strings.ToLower(probe.Header("Server"))
	xpb := strings.ToLower(probe.Header("X-Powered-By"))
	via := strings.ToLower(probe.Header("Via"))
	xgeneratedby := strings.ToLower(probe.Header("X-Generated-By"))

	// ── Servers ───────────────────────────────────────────────────────────
	switch {
	case strings.Contains(server, "nginx"):
		add("Nginx")
	case strings.Contains(server, "apache"):
		add("Apache")
	case strings.Contains(server, "microsoft-iis"):
		add("IIS")
	case strings.Contains(server, "litespeed"):
		add("LiteSpeed")
	case strings.Contains(server, "caddy"):
		add("Caddy")
	case strings.Contains(server, "cloudflare"):
		add("Cloudflare")
	case strings.Contains(server, "amazons3"):
		add("AWS S3")
	case strings.Contains(server, "awselb"):
		add("AWS ELB")
	case strings.Contains(server, "squarespace"):
		add("Squarespace")
	case strings.Contains(server, "netlify"):
		add("Netlify")
	case strings.Contains(server, "github.com"):
		add("GitHub Pages")
	case strings.Contains(server, "vercel"):
		add("Vercel")
	case strings.Contains(server, "firebase"):
		add("Firebase Hosting")
	case strings.Contains(server, "render"):
		add("Render")
	}

	// ── Frameworks via X-Powered-By ───────────────────────────────────────
	switch {
	case strings.Contains(xpb, "php"):
		add("PHP")
	case strings.Contains(xpb, "asp.net"):
		add("ASP.NET")
	case strings.Contains(xpb, "express"):
		add("Express.js")
	case strings.Contains(xpb, "next.js"):
		add("Next.js")
	case strings.Contains(xpb, "django"):
		add("Django")
	case strings.Contains(xpb, "rails"):
		add("Ruby on Rails")
	}

	// ── CDN / Proxy indicators ───────────────────────────────────────────
	if strings.Contains(via, "cloudfront") {
		add("AWS CloudFront")
	}
	if strings.Contains(via, "fastly") {
		add("Fastly")
	}
	if strings.Contains(via, "varnish") {
		add("Varnish")
	}

	// ── CMS-specific headers ─────────────────────────────────────────────
	if probe.HasHeader("X-Shopify-Stage") || probe.HasHeader("X-ShopID") {
		add("Shopify")
	}
	if probe.HasHeader("X-WF-Request-ID") {
		add("Webflow")
	}
	if probe.HasHeader("X-Ghost-Cache-Status") {
		add("Ghost")
	}
	if probe.HasHeader("X-Zendesk-Origin-Server") || probe.HasHeader("X-Zendesk-Request-ID") {
		add("Zendesk")
	}
	if probe.HasHeader("X-HubSpot-Request-ID") {
		add("HubSpot")
	}
	if probe.HasHeader("X-NF-Request-ID") {
		add("Netlify")
	}
	if probe.HasHeader("X-Vercel-ID") {
		add("Vercel")
	}
	if probe.HasHeader("Fly-Request-ID") {
		add("Fly.io")
	}
	if probe.HasHeader("X-Heroku-Error-ID") {
		add("Heroku")
	}
	if probe.HasHeader("X-Amz-Request-ID") || probe.HasHeader("X-Amz-CF-ID") {
		add("AWS")
	}
	if probe.HasHeader("X-MS-Request-ID") {
		add("Azure")
	}

	// ── Intercom ──────────────────────────────────────────────────────────
	if probe.HasHeader("X-Intercom-Frame-Nonce") {
		add("Intercom")
	}

	// X-Generated-By
	if strings.Contains(xgeneratedby, "wordpress") {
		add("WordPress")
	}
	if strings.Contains(xgeneratedby, "joomla") {
		add("Joomla")
	}
	if strings.Contains(xgeneratedby, "drupal") {
		add("Drupal")
	}
}

// ─── Body-based detection ────────────────────────────────────────────────────

// bodySignature maps a body substring to a technology name.
type bodySignature struct {
	pattern  string
	caseInsn bool
	tech     string
}

var bodySignatures = []bodySignature{
	// CMS
	{pattern: "/wp-content/", tech: "WordPress"},
	{pattern: "/wp-includes/", tech: "WordPress"},
	{pattern: "Joomla!", caseInsn: true, tech: "Joomla"},
	{pattern: "Drupal.settings", tech: "Drupal"},
	{pattern: "sites/default/files", tech: "Drupal"},
	{pattern: "magento", caseInsn: true, tech: "Magento"},
	{pattern: "typo3", caseInsn: true, tech: "TYPO3"},
	{pattern: "ghost.io", tech: "Ghost"},

	// Cloud platforms (error pages)
	{pattern: "NoSuchBucket", tech: "AWS S3"},
	{pattern: "The specified bucket does not exist", tech: "AWS S3"},
	{pattern: "ERROR: The request could not be satisfied", tech: "AWS CloudFront"},
	{pattern: "There isn't a GitHub Pages site here", tech: "GitHub Pages"},
	{pattern: "No such app", tech: "Heroku"},
	{pattern: "Not Found - Request ID", tech: "Netlify"},
	{pattern: "The deployment could not be found", tech: "Vercel"},
	{pattern: "service not found", caseInsn: true, tech: "Render"},
	{pattern: "app not found", caseInsn: true, tech: "Fly.io"},
	{pattern: "domain is not configured", caseInsn: true, tech: "DigitalOcean"},
	{pattern: "This site is not available", tech: "Webflow"},
	{pattern: "Help Center Closed", tech: "Zendesk"},
	{pattern: "Domain not found", tech: "HubSpot"},
	{pattern: "Sorry, this shop is currently unavailable", tech: "Shopify"},
	{pattern: "There is no helpdesk here", tech: "Freshdesk"},
	{pattern: "Unknown Project", tech: "Read the Docs"},
	{pattern: "project not found", tech: "Surge.sh"},
	{pattern: "Repository not found", tech: "Bitbucket Pages"},
	{pattern: "This UserVoice subdomain is currently available!", tech: "UserVoice"},
	{pattern: "This page is reserved for artistic dogs", tech: "Intercom"},
	{pattern: "404 Web Site not found", tech: "Azure Web Apps"},
	{pattern: "BlobNotFound", tech: "Azure Blob Storage"},
	{pattern: "Site Not Found", tech: "Firebase Hosting"},
	{pattern: "Fastly error: unknown domain", tech: "Fastly"},

	// JS Frameworks (very common in body)
	{pattern: "react", caseInsn: true, tech: "React"},
	{pattern: "__NEXT_DATA__", tech: "Next.js"},
	{pattern: "nuxt", caseInsn: true, tech: "Nuxt.js"},
	{pattern: "ng-version=", tech: "Angular"},
	{pattern: "vue.js", caseInsn: true, tech: "Vue.js"},
	{pattern: "svelte", caseInsn: true, tech: "Svelte"},
	{pattern: "gatsby-", tech: "Gatsby"},

	// Analytics
	{pattern: "google-analytics.com", tech: "Google Analytics"},
	{pattern: "gtag(", tech: "Google Tag Manager"},
	{pattern: "segment.io", caseInsn: true, tech: "Segment"},
	{pattern: "hotjar", caseInsn: true, tech: "Hotjar"},

	// E-commerce
	{pattern: "shopify", caseInsn: true, tech: "Shopify"},
	{pattern: "woocommerce", caseInsn: true, tech: "WooCommerce"},
	{pattern: "bigcommerce", caseInsn: true, tech: "BigCommerce"},
}

func detectFromBody(probe *models.HTTPProbe, add adder) {
	if len(probe.Body) == 0 {
		return
	}
	body := string(probe.Body)

	for _, sig := range bodySignatures {
		if sig.caseInsn {
			if strings.Contains(strings.ToLower(body), strings.ToLower(sig.pattern)) {
				add(sig.tech)
			}
		} else {
			if strings.Contains(body, sig.pattern) {
				add(sig.tech)
			}
		}
	}
}

// ─── TLS-based detection ─────────────────────────────────────────────────────

func detectFromTLS(probe *models.HTTPProbe, add adder) {
	subject := strings.ToLower(probe.TLSSubject)
	issuer := strings.ToLower(probe.TLSIssuer)

	switch {
	case strings.Contains(subject, "cloudflare"):
		add("Cloudflare")
	case strings.Contains(subject, "amazonaws.com"):
		add("AWS")
	case strings.Contains(subject, "azure"):
		add("Azure")
	case strings.Contains(issuer, "let's encrypt") || strings.Contains(issuer, "letsencrypt"):
		add("Let's Encrypt TLS")
	case strings.Contains(issuer, "digicert"):
		add("DigiCert TLS")
	case strings.Contains(issuer, "sectigo") || strings.Contains(issuer, "comodo"):
		add("Sectigo TLS")
	case strings.Contains(issuer, "zerossl"):
		add("ZeroSSL")
	}
}
