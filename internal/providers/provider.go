// Package providers defines the Provider type, all known provider definitions,
// and the Registry that groups them together.
//
// All definitions live in this single package to avoid import cycles.
package providers

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/MrEx-Right/SubReaper/internal/models"
)

// ── Provider interface types ─────────────────────────────────────────────────

// HeaderMatch describes a header key + value that, if present in an HTTP
// response, contributes to identifying a specific provider.
type HeaderMatch struct {
	Key      string // HTTP header name (case-insensitive)
	Contains string // Substring the header value must contain (empty = presence only)
}

// BodySignal describes a body substring that may indicate a specific provider's
// error page. Body signals are lowest-priority evidence and are never sufficient
// alone for a confirmed match.
type BodySignal struct {
	Contains   string
	CaseInsens bool
}

// ClaimCheckFn is a function that actively verifies whether a resource at the
// given dangling CNAME endpoint is available to claim.
type ClaimCheckFn func(ctx context.Context, cname string) (bool, error)

// Provider defines all detection signals and verification logic for a single
// cloud service known to be vulnerable to subdomain takeover.
type Provider struct {
	Name            string
	CNAMESuffixes   []string
	IPRanges        []*net.IPNet
	TLSCertContains []string
	Headers         []HeaderMatch
	BodySignals     []BodySignal
	ClaimCheck      ClaimCheckFn
	TakeoverDoc     string
	ClaimURL        string
}

// Score computes the confidence score from accumulated signals. Max 100.
func (p *Provider) Score(signals []models.Signal) int {
	total := 0
	for _, s := range signals {
		total += s.Points
	}
	if total > 100 {
		return 100
	}
	return total
}

// MatchCNAME checks whether the CNAME value matches any known suffix.
func (p *Provider) MatchCNAME(cname string) string {
	lower := strings.ToLower(cname)
	for _, suffix := range p.CNAMESuffixes {
		if strings.HasSuffix(lower, strings.ToLower(suffix)) {
			return suffix
		}
	}
	return ""
}

// MatchIP checks whether the IP falls within any known provider range.
func (p *Provider) MatchIP(ip net.IP) bool {
	for _, cidr := range p.IPRanges {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// MatchHeader checks provider header patterns against a response header map.
func (p *Provider) MatchHeader(headers map[string][]string) []string {
	var matched []string
	for _, hm := range p.Headers {
		for k, vals := range headers {
			if !strings.EqualFold(k, hm.Key) {
				continue
			}
			for _, v := range vals {
				if hm.Contains == "" || strings.Contains(strings.ToLower(v), strings.ToLower(hm.Contains)) {
					matched = append(matched, hm.Key+": "+v)
				}
			}
		}
	}
	return matched
}

// MatchBody checks provider body signals against a response body string.
func (p *Provider) MatchBody(body string) []string {
	var matched []string
	for _, bs := range p.BodySignals {
		haystack := body
		needle := bs.Contains
		if bs.CaseInsens {
			haystack = strings.ToLower(haystack)
			needle = strings.ToLower(needle)
		}
		if strings.Contains(haystack, needle) {
			matched = append(matched, bs.Contains)
		}
	}
	return matched
}

// ── Registry ─────────────────────────────────────────────────────────────────

// Registry holds all known providers.
type Registry struct {
	providers []*Provider
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry { return &Registry{} }

// Register adds a provider.
func (r *Registry) Register(p *Provider) { r.providers = append(r.providers, p) }

// All returns all registered providers.
func (r *Registry) All() []*Provider { return r.providers }

// Len returns the number of registered providers.
func (r *Registry) Len() int { return len(r.providers) }

// DefaultRegistry returns a registry pre-loaded with all known providers.
func DefaultRegistry() *Registry {
	r := NewRegistry()
	for _, p := range allProviders() {
		r.Register(p)
	}
	return r
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func parseCIDRs(cidrs []string) []*net.IPNet {
	var nets []*net.IPNet
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			nets = append(nets, ipNet)
		}
	}
	return nets
}

func dnsNXDomainCheck(ctx context.Context, cname string) (bool, error) {
	addrs, err := net.DefaultResolver.LookupHost(ctx, cname)
	if err != nil {
		return true, nil
	}
	return len(addrs) == 0, nil
}

func httpGetCheck(ctx context.Context, url string, expectedStatus int) (bool, error) {
	client := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", "SubReaper-Scanner")
	resp, err := client.Do(req)
	if err != nil {
		return true, nil
	}
	defer resp.Body.Close()
	return resp.StatusCode == expectedStatus, nil
}

// ── Provider Definitions ─────────────────────────────────────────────────────

func allProviders() []*Provider {
	return []*Provider{
		// ── AWS ──────────────────────────────────────────────────────────────
		{
			Name: "AWS S3",
			CNAMESuffixes: []string{
				".s3.amazonaws.com",
				".s3-website.us-east-1.amazonaws.com",
				".s3-website.us-east-2.amazonaws.com",
				".s3-website.us-west-1.amazonaws.com",
				".s3-website.us-west-2.amazonaws.com",
				".s3-website.eu-west-1.amazonaws.com",
				".s3-website.eu-central-1.amazonaws.com",
				".s3-website.ap-southeast-1.amazonaws.com",
				".s3-website.ap-northeast-1.amazonaws.com",
				".s3-website-us-east-1.amazonaws.com",
				".s3-website-eu-west-1.amazonaws.com",
			},
			Headers: []HeaderMatch{
				{Key: "x-amz-request-id"},
				{Key: "x-amz-id-2"},
				{Key: "server", Contains: "AmazonS3"},
			},
			BodySignals: []BodySignal{
				{Contains: "NoSuchBucket"},
				{Contains: "The specified bucket does not exist"},
			},
			ClaimCheck: func(ctx context.Context, cname string) (bool, error) {
				parts := strings.Split(strings.ToLower(cname), ".")
				if len(parts) < 3 {
					return false, nil
				}
				bucketName := parts[0]
				if bucketName == "" {
					return false, nil
				}
				return httpGetCheck(ctx, fmt.Sprintf("https://%s.s3.amazonaws.com/", bucketName), http.StatusNotFound)
			},
			TakeoverDoc: "https://hackerone.com/reports/207477",
			ClaimURL:    "https://s3.console.aws.amazon.com/s3/home",
		},
		{
			Name:          "AWS CloudFront",
			CNAMESuffixes: []string{".cloudfront.net"},
			Headers: []HeaderMatch{
				{Key: "x-cache", Contains: "cloudfront"},
				{Key: "via", Contains: "cloudfront"},
				{Key: "x-amz-cf-id"},
			},
			BodySignals: []BodySignal{
				{Contains: "ERROR: The request could not be satisfied"},
				{Contains: "CloudFront wasn't able to connect to the origin"},
			},
			TakeoverDoc: "https://github.com/EdOverflow/can-i-take-over-xyz",
			ClaimURL:    "https://console.aws.amazon.com/cloudfront/home",
		},
		{
			Name:          "AWS Elastic Beanstalk",
			CNAMESuffixes: []string{".elasticbeanstalk.com"},
			BodySignals:   []BodySignal{{Contains: "No Application"}},
			TakeoverDoc:   "https://github.com/EdOverflow/can-i-take-over-xyz",
		},

		// ── Azure ─────────────────────────────────────────────────────────────
		{
			Name:          "Azure Web Apps",
			CNAMESuffixes: []string{".azurewebsites.net", ".cloudapp.net", ".cloudapp.azure.com"},
			Headers: []HeaderMatch{
				{Key: "x-ms-request-id"},
				{Key: "x-powered-by", Contains: "ASP.NET"},
			},
			BodySignals: []BodySignal{
				{Contains: "404 Web Site not found"},
				{Contains: "Microsoft Azure App Service"},
			},
			ClaimCheck: func(ctx context.Context, cname string) (bool, error) {
				if !strings.HasSuffix(strings.ToLower(cname), ".azurewebsites.net") {
					return false, nil
				}
				return dnsNXDomainCheck(ctx, cname)
			},
			TakeoverDoc: "https://github.com/EdOverflow/can-i-take-over-xyz",
		},
		{
			Name: "Azure Blob Storage",
			CNAMESuffixes: []string{
				".blob.core.windows.net",
				".z1.web.core.windows.net", ".z2.web.core.windows.net",
				".z3.web.core.windows.net", ".z4.web.core.windows.net",
				".z5.web.core.windows.net", ".z13.web.core.windows.net",
				".z22.web.core.windows.net",
			},
			Headers: []HeaderMatch{
				{Key: "x-ms-request-id"},
				{Key: "x-ms-version"},
			},
			BodySignals: []BodySignal{
				{Contains: "BlobNotFound"},
				{Contains: "ContainerNotFound"},
				{Contains: "The specified container does not exist"},
			},
			TakeoverDoc: "https://github.com/EdOverflow/can-i-take-over-xyz",
		},
		{
			Name:          "Azure Traffic Manager",
			CNAMESuffixes: []string{".trafficmanager.net"},
			BodySignals:   []BodySignal{{Contains: "Error 404 - Not found", CaseInsens: true}},
			TakeoverDoc:   "https://github.com/EdOverflow/can-i-take-over-xyz",
		},

		// ── GitHub ────────────────────────────────────────────────────────────
		{
			Name:          "GitHub Pages",
			CNAMESuffixes: []string{".github.io"},
			Headers: []HeaderMatch{
				{Key: "server", Contains: "GitHub.com"},
				{Key: "x-github-request-id"},
			},
			BodySignals: []BodySignal{
				{Contains: "There isn't a GitHub Pages site here"},
			},
			ClaimCheck: func(ctx context.Context, cname string) (bool, error) {
				lower := strings.ToLower(cname)
				trimmed := strings.TrimSuffix(strings.TrimSuffix(lower, "."), ".github.io")
				if strings.Contains(trimmed, ".") {
					return false, nil
				}
				if trimmed == "" {
					return false, nil
				}
				client := &http.Client{Timeout: 8 * time.Second}
				req, err := http.NewRequestWithContext(ctx, http.MethodGet,
					"https://api.github.com/users/"+trimmed, nil)
				if err != nil {
					return false, err
				}
				req.Header.Set("Accept", "application/vnd.github.v3+json")
				req.Header.Set("User-Agent", "SubReaper-Scanner")
				resp, err := client.Do(req)
				if err != nil {
					return false, err
				}
				defer resp.Body.Close()
				return resp.StatusCode == http.StatusNotFound, nil
			},
			TakeoverDoc: "https://hackerone.com/reports/263902",
			ClaimURL:    "https://github.com/new",
		},

		// ── Heroku ────────────────────────────────────────────────────────────
		{
			Name:          "Heroku",
			CNAMESuffixes: []string{".herokuapp.com", ".herokussl.com"},
			Headers: []HeaderMatch{
				{Key: "via", Contains: "heroku"},
				{Key: "x-heroku-error-id"},
			},
			BodySignals: []BodySignal{
				{Contains: "No such app"},
				{Contains: "herokucdn.com/error-pages/no-such-app.html"},
			},
			ClaimCheck: func(ctx context.Context, cname string) (bool, error) {
				if !strings.HasSuffix(strings.ToLower(cname), ".herokuapp.com") {
					return false, nil
				}
				client := &http.Client{
					Timeout: 8 * time.Second,
					CheckRedirect: func(req *http.Request, via []*http.Request) error {
						return http.ErrUseLastResponse
					},
				}
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+cname, nil)
				if err != nil {
					return false, err
				}
				req.Header.Set("User-Agent", "SubReaper-Scanner")
				resp, err := client.Do(req)
				if err != nil {
					return true, nil
				}
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusNotFound {
					via := strings.ToLower(resp.Header.Get("Via"))
					server := strings.ToLower(resp.Header.Get("Server"))
					return strings.Contains(via, "heroku") || strings.Contains(server, "heroku"), nil
				}
				return false, nil
			},
			TakeoverDoc: "https://hackerone.com/reports/340139",
			ClaimURL:    "https://dashboard.heroku.com/new-app",
		},

		// ── Modern Hosting ────────────────────────────────────────────────────
		{
			Name:          "Netlify",
			CNAMESuffixes: []string{".netlify.app", ".netlify.com"},
			Headers: []HeaderMatch{
				{Key: "server", Contains: "Netlify"},
				{Key: "x-nf-request-id"},
			},
			BodySignals: []BodySignal{
				{Contains: "Not Found - Request ID"},
			},
			ClaimCheck: func(ctx context.Context, cname string) (bool, error) {
				lower := strings.ToLower(cname)
				if !strings.HasSuffix(lower, ".netlify.app") && !strings.HasSuffix(lower, ".netlify.com") {
					return false, nil
				}
				return dnsNXDomainCheck(ctx, cname)
			},
			TakeoverDoc: "https://github.com/EdOverflow/can-i-take-over-xyz",
			ClaimURL:    "https://app.netlify.com/",
		},
		{
			Name:          "Vercel",
			CNAMESuffixes: []string{".vercel.app", ".now.sh"},
			Headers: []HeaderMatch{
				{Key: "server", Contains: "Vercel"},
				{Key: "x-vercel-id"},
			},
			BodySignals: []BodySignal{
				{Contains: "The deployment could not be found"},
			},
			ClaimCheck: func(ctx context.Context, cname string) (bool, error) {
				if !strings.HasSuffix(strings.ToLower(cname), ".vercel.app") {
					return false, nil
				}
				return dnsNXDomainCheck(ctx, cname)
			},
			TakeoverDoc: "https://github.com/EdOverflow/can-i-take-over-xyz",
			ClaimURL:    "https://vercel.com/new",
		},
		{
			Name:          "Render",
			CNAMESuffixes: []string{".onrender.com"},
			Headers:       []HeaderMatch{{Key: "server", Contains: "Render"}},
			BodySignals:   []BodySignal{{Contains: "service not found", CaseInsens: true}},
			ClaimCheck: func(ctx context.Context, cname string) (bool, error) {
				return httpGetCheck(ctx, "https://"+cname, http.StatusNotFound)
			},
			TakeoverDoc: "https://github.com/EdOverflow/can-i-take-over-xyz",
		},
		{
			Name:          "Fly.io",
			CNAMESuffixes: []string{".fly.dev"},
			Headers:       []HeaderMatch{{Key: "fly-request-id"}},
			BodySignals:   []BodySignal{{Contains: "app not found", CaseInsens: true}},
			ClaimCheck: func(ctx context.Context, cname string) (bool, error) {
				if !strings.HasSuffix(strings.ToLower(cname), ".fly.dev") {
					return false, nil
				}
				return dnsNXDomainCheck(ctx, cname)
			},
			TakeoverDoc: "https://github.com/EdOverflow/can-i-take-over-xyz",
		},
		{
			Name:          "DigitalOcean App Platform",
			CNAMESuffixes: []string{".ondigitalocean.app"},
			BodySignals:   []BodySignal{{Contains: "domain is not configured", CaseInsens: true}},
			TakeoverDoc:   "https://github.com/EdOverflow/can-i-take-over-xyz",
		},
		{
			Name:          "Webflow",
			CNAMESuffixes: []string{".webflow.io"},
			Headers:       []HeaderMatch{{Key: "x-wf-request-id"}},
			BodySignals:   []BodySignal{{Contains: "This site is not available"}},
			TakeoverDoc:   "https://github.com/EdOverflow/can-i-take-over-xyz",
		},
		{
			Name:          "Firebase Hosting",
			CNAMESuffixes: []string{".web.app", ".firebaseapp.com"},
			Headers:       []HeaderMatch{{Key: "server", Contains: "Firebase"}},
			BodySignals:   []BodySignal{{Contains: "Site Not Found"}},
			ClaimCheck: func(ctx context.Context, cname string) (bool, error) {
				lower := strings.ToLower(cname)
				if !strings.HasSuffix(lower, ".web.app") && !strings.HasSuffix(lower, ".firebaseapp.com") {
					return false, nil
				}
				return dnsNXDomainCheck(ctx, cname)
			},
			TakeoverDoc: "https://github.com/EdOverflow/can-i-take-over-xyz",
		},

		// ── SaaS / CMS ────────────────────────────────────────────────────────
		{
			Name:          "Shopify",
			CNAMESuffixes: []string{".myshopify.com"},
			Headers: []HeaderMatch{
				{Key: "x-shopid"},
				{Key: "x-shopify-stage"},
			},
			BodySignals: []BodySignal{
				{Contains: "Sorry, this shop is currently unavailable"},
			},
			ClaimCheck: func(ctx context.Context, cname string) (bool, error) {
				return httpGetCheck(ctx, "https://"+cname, http.StatusNotFound)
			},
			TakeoverDoc: "https://github.com/EdOverflow/can-i-take-over-xyz",
			ClaimURL:    "https://accounts.shopify.com/store-login",
		},
		{
			Name:          "Tumblr",
			CNAMESuffixes: []string{".tumblr.com"},
			BodySignals: []BodySignal{
				{Contains: "Whatever you were looking for doesn't live here"},
			},
			TakeoverDoc: "https://github.com/EdOverflow/can-i-take-over-xyz",
		},
		{
			Name:          "Ghost",
			CNAMESuffixes: []string{".ghost.io"},
			Headers:       []HeaderMatch{{Key: "x-ghost-cache-status"}},
			BodySignals:   []BodySignal{{Contains: "The thing you were looking for is no longer here"}},
			ClaimCheck: func(ctx context.Context, cname string) (bool, error) {
				if !strings.HasSuffix(strings.ToLower(cname), ".ghost.io") {
					return false, nil
				}
				return dnsNXDomainCheck(ctx, cname)
			},
			TakeoverDoc: "https://github.com/EdOverflow/can-i-take-over-xyz",
		},
		{
			Name:          "Zendesk",
			CNAMESuffixes: []string{".zendesk.com"},
			Headers: []HeaderMatch{
				{Key: "x-zendesk-origin-server"},
				{Key: "x-zendesk-request-id"},
			},
			BodySignals: []BodySignal{
				{Contains: "Help Center Closed"},
				{Contains: "Oops, this help center no longer exists"},
			},
			TakeoverDoc: "https://github.com/EdOverflow/can-i-take-over-xyz",
		},
		{
			Name:          "Freshdesk",
			CNAMESuffixes: []string{".freshdesk.com"},
			BodySignals:   []BodySignal{{Contains: "There is no helpdesk here"}},
			TakeoverDoc:   "https://github.com/EdOverflow/can-i-take-over-xyz",
		},
		{
			Name:          "HubSpot",
			CNAMESuffixes: []string{".hubspot.com", ".hubspotpagebuilder.com", ".hs-sites.com"},
			Headers:       []HeaderMatch{{Key: "x-hubspot-request-id"}},
			BodySignals: []BodySignal{
				{Contains: "Domain not found"},
				{Contains: "This domain hasn't been connected"},
			},
			TakeoverDoc: "https://github.com/EdOverflow/can-i-take-over-xyz",
		},
		{
			Name:          "Surge.sh",
			CNAMESuffixes: []string{".surge.sh"},
			BodySignals:   []BodySignal{{Contains: "project not found"}},
			ClaimCheck: func(ctx context.Context, cname string) (bool, error) {
				if !strings.HasSuffix(strings.ToLower(cname), ".surge.sh") {
					return false, nil
				}
				return dnsNXDomainCheck(ctx, cname)
			},
			TakeoverDoc: "https://github.com/EdOverflow/can-i-take-over-xyz",
		},
		{
			Name:          "Pantheon",
			CNAMESuffixes: []string{".pantheonsite.io"},
			BodySignals:   []BodySignal{{Contains: "The gods are wise, but do not know of the site which you seek"}},
			TakeoverDoc:   "https://github.com/EdOverflow/can-i-take-over-xyz",
		},
		{
			Name:          "Read the Docs",
			CNAMESuffixes: []string{".readthedocs.io", ".readthedocs.org"},
			BodySignals:   []BodySignal{{Contains: "Unknown Project"}},
			ClaimCheck: func(ctx context.Context, cname string) (bool, error) {
				return dnsNXDomainCheck(ctx, cname)
			},
			TakeoverDoc: "https://github.com/EdOverflow/can-i-take-over-xyz",
		},
		{
			Name:          "Fastly",
			CNAMESuffixes: []string{".global.prod.fastly.net", ".fastly.net"},
			Headers: []HeaderMatch{
				{Key: "x-served-by", Contains: "cache"},
				{Key: "fastly-restarts"},
				{Key: "x-fastly-request-id"},
			},
			BodySignals: []BodySignal{
				{Contains: "Fastly error: unknown domain"},
				{Contains: "Please check that this domain has been added to a service"},
			},
			TakeoverDoc: "https://github.com/EdOverflow/can-i-take-over-xyz",
		},
		{
			Name:          "Bitbucket Pages",
			CNAMESuffixes: []string{".bitbucket.io"},
			BodySignals:   []BodySignal{{Contains: "Repository not found"}},
			ClaimCheck: func(ctx context.Context, cname string) (bool, error) {
				return dnsNXDomainCheck(ctx, cname)
			},
			TakeoverDoc: "https://github.com/EdOverflow/can-i-take-over-xyz",
		},
		{
			Name:          "UserVoice",
			CNAMESuffixes: []string{".uservoice.com"},
			BodySignals:   []BodySignal{{Contains: "This UserVoice subdomain is currently available!"}},
			TakeoverDoc:   "https://github.com/EdOverflow/can-i-take-over-xyz",
		},
		{
			Name:          "Intercom",
			CNAMESuffixes: []string{".intercom.io", ".custom.intercom.io"},
			Headers:       []HeaderMatch{{Key: "x-intercom-frame-nonce"}},
			BodySignals:   []BodySignal{{Contains: "This page is reserved for artistic dogs"}},
			TakeoverDoc:   "https://github.com/EdOverflow/can-i-take-over-xyz",
		},
		{
			Name:          "WordPress.com",
			CNAMESuffixes: []string{".wordpress.com"},
			Headers:       []HeaderMatch{{Key: "x-hacker"}},
			BodySignals:   []BodySignal{{Contains: "Do you want to register"}},
			TakeoverDoc:   "https://github.com/EdOverflow/can-i-take-over-xyz",
		},
		{
			Name:          "Squarespace",
			CNAMESuffixes: []string{".squarespace.com"},
			Headers:       []HeaderMatch{{Key: "server", Contains: "Squarespace"}},
			BodySignals:   []BodySignal{{Contains: "No Such Account"}},
			TakeoverDoc:   "https://github.com/EdOverflow/can-i-take-over-xyz",
		},
		{
			Name:          "Cargo Collective",
			CNAMESuffixes: []string{".cargocollective.com"},
			BodySignals:   []BodySignal{{Contains: "If you're moving your domain away from Cargo"}},
			TakeoverDoc:   "https://github.com/EdOverflow/can-i-take-over-xyz",
		},
		{
			Name:          "Agile CRM",
			CNAMESuffixes: []string{".agilecrm.com"},
			BodySignals:   []BodySignal{{Contains: "Sorry, this page is no longer available"}},
			TakeoverDoc:   "https://github.com/EdOverflow/can-i-take-over-xyz",
		},
	}
}
