// Package providers defines the Provider type, all known provider definitions,
// and the Registry that groups them together.
//
// All definitions live in this single package to avoid import cycles.
//
// Status values and unclaimed-resource fingerprints follow
// https://github.com/EdOverflow/can-i-take-over-xyz.
package providers

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
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

// BodySignal describes a body substring that appears on a provider's
// "unclaimed resource" page. Body signals are evidence that the resource is
// unclaimed, but they are never sufficient alone for a match: the CNAME must
// also point at the provider.
type BodySignal struct {
	Contains   string
	CaseInsens bool
}

// CheckEnv carries the network helpers a claim check may use, so checks use
// the scanner's own resolvers and timeouts.
type CheckEnv struct {
	// IsNXDOMAIN reports whether host returns NXDOMAIN. Resolution errors
	// must be returned as errors.
	IsNXDOMAIN func(ctx context.Context, host string) (bool, error)
	// HTTP is the client used for HTTP checks. Redirects are not followed.
	HTTP *http.Client
}

// ClaimCheckFn actively verifies whether the resource behind cname is
// available to claim. Any network error must be returned as an error and
// never reported as claimable.
type ClaimCheckFn func(ctx context.Context, env *CheckEnv, cname string) (bool, error)

// Provider defines all detection signals and verification logic for a single
// cloud service known to be vulnerable to subdomain takeover.
type Provider struct {
	Name            string
	Status          models.ProviderStatus
	CNAMESuffixes   []string
	CNAMEPatterns   []*regexp.Regexp
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

// MatchCNAME checks whether the CNAME value matches any known suffix or pattern.
// It returns the matched suffix/pattern, or "".
func (p *Provider) MatchCNAME(cname string) string {
	lower := strings.ToLower(strings.TrimSuffix(cname, "."))
	for _, suffix := range p.CNAMESuffixes {
		if strings.HasSuffix(lower, strings.ToLower(suffix)) {
			return suffix
		}
	}
	for _, re := range p.CNAMEPatterns {
		if re.MatchString(lower) {
			return re.String()
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
	lowerBody := ""
	for _, bs := range p.BodySignals {
		if bs.CaseInsens {
			if lowerBody == "" {
				lowerBody = strings.ToLower(body)
			}
			if strings.Contains(lowerBody, strings.ToLower(bs.Contains)) {
				matched = append(matched, bs.Contains)
			}
			continue
		}
		if strings.Contains(body, bs.Contains) {
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

// Get returns the provider with the given name, or nil.
func (r *Registry) Get(name string) *Provider {
	for _, p := range r.providers {
		if strings.EqualFold(p.Name, name) {
			return p
		}
	}
	return nil
}

// MatchAnyCNAME reports whether any of the CNAME targets belongs to a
// registered provider.
func (r *Registry) MatchAnyCNAME(targets []string) bool {
	for _, t := range targets {
		for _, p := range r.providers {
			if p.MatchCNAME(t) != "" {
				return true
			}
		}
	}
	return false
}

// DefaultRegistry returns a registry pre-loaded with all known providers.
func DefaultRegistry() *Registry {
	r := NewRegistry()
	for _, p := range allProviders() {
		r.Register(p)
	}
	return r
}

// ── Claim-check helpers ──────────────────────────────────────────────────────

const claimBodyLimit = 64 * 1024

// DefaultHTTPClient returns the client used for claim checks.
func DefaultHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// fetch performs a GET and returns the status code and a bounded body.
func fetch(ctx context.Context, env *CheckEnv, url string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("User-Agent", "SubReaper/2.0 (+https://github.com/MrEx-Right/SubReaper)")
	resp, err := env.HTTP.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, claimBodyLimit))
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(body), nil
}

// nxClaim returns a check that is positive only when cname returns NXDOMAIN
// and ends in one of the given suffixes (names under those suffixes can be
// registered by anyone).
func nxClaim(suffixes ...string) ClaimCheckFn {
	return func(ctx context.Context, env *CheckEnv, cname string) (bool, error) {
		lower := strings.ToLower(cname)
		ok := false
		for _, s := range suffixes {
			if strings.HasSuffix(lower, s) {
				ok = true
				break
			}
		}
		if !ok || env == nil || env.IsNXDOMAIN == nil {
			return false, nil
		}
		return env.IsNXDOMAIN(ctx, cname)
	}
}

// bodyClaim returns a check that requests the CNAME target itself (HTTPS
// first, then HTTP) and is positive only when the provider's unclaimed-name
// page is served for it. This fits providers with wildcard DNS, where the
// target always resolves and only the response shows the name is free.
func bodyClaim(markers ...string) ClaimCheckFn {
	return func(ctx context.Context, env *CheckEnv, cname string) (bool, error) {
		if env == nil || env.HTTP == nil {
			return false, nil
		}
		var lastErr error
		for _, scheme := range []string{"https://", "http://"} {
			_, body, err := fetch(ctx, env, scheme+cname+"/")
			if err != nil {
				lastErr = err
				continue
			}
			for _, m := range markers {
				if strings.Contains(body, m) {
					return true, nil
				}
			}
			return false, nil
		}
		return false, lastErr
	}
}

var s3Suffix = regexp.MustCompile(`\.(s3|s3-website|s3-external-1)([.-][a-z0-9-]+)?(\.dualstack)?(\.[a-z0-9-]+)?\.amazonaws\.com$`)

// s3Claim checks whether the bucket named by the CNAME target exists.
func s3Claim(ctx context.Context, env *CheckEnv, cname string) (bool, error) {
	lower := strings.ToLower(cname)
	loc := s3Suffix.FindStringIndex(lower)
	if loc == nil || loc[0] == 0 || env == nil || env.HTTP == nil {
		return false, nil
	}
	bucket := lower[:loc[0]]
	status, body, err := fetch(ctx, env, "https://s3.amazonaws.com/"+bucket+"/")
	if err != nil {
		return false, err
	}
	return status == http.StatusNotFound && strings.Contains(body, "NoSuchBucket"), nil
}

// githubClaim checks whether the GitHub account behind <user>.github.io exists.
// A missing account means anyone can register it and publish the site.
func githubClaim(ctx context.Context, env *CheckEnv, cname string) (bool, error) {
	lower := strings.ToLower(strings.TrimSuffix(cname, "."))
	user := strings.TrimSuffix(lower, ".github.io")
	if user == lower || user == "" || strings.Contains(user, ".") || env == nil || env.HTTP == nil {
		return false, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/users/"+user, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "SubReaper/2.0")
	resp, err := env.HTTP.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotFound:
		return true, nil
	case http.StatusOK:
		return false, nil
	default:
		return false, fmt.Errorf("github api returned HTTP %d", resp.StatusCode)
	}
}

// ── Provider Definitions ─────────────────────────────────────────────────────

const xyz = "https://github.com/EdOverflow/can-i-take-over-xyz"

func allProviders() []*Provider {
	return []*Provider{
		// ── AWS ──────────────────────────────────────────────────────────────
		{
			Name:          "AWS S3",
			Status:        models.StatusVulnerable,
			CNAMEPatterns: []*regexp.Regexp{s3Suffix},
			Headers: []HeaderMatch{
				{Key: "x-amz-request-id"},
				{Key: "x-amz-id-2"},
				{Key: "server", Contains: "AmazonS3"},
			},
			BodySignals: []BodySignal{
				{Contains: "NoSuchBucket"},
				{Contains: "The specified bucket does not exist"},
			},
			ClaimCheck:  s3Claim,
			TakeoverDoc: "https://hackerone.com/reports/207477",
			ClaimURL:    "https://s3.console.aws.amazon.com/s3/home",
		},
		{
			Name:          "AWS Elastic Beanstalk",
			Status:        models.StatusVulnerable,
			CNAMESuffixes: []string{".elasticbeanstalk.com"},
			ClaimCheck:    nxClaim(".elasticbeanstalk.com"),
			TakeoverDoc:   xyz,
			ClaimURL:      "https://console.aws.amazon.com/elasticbeanstalk/home",
		},
		{
			Name:          "AWS CloudFront",
			Status:        models.StatusNotVulnerable,
			CNAMESuffixes: []string{".cloudfront.net"},
			Headers: []HeaderMatch{
				{Key: "x-cache", Contains: "cloudfront"},
				{Key: "via", Contains: "cloudfront"},
				{Key: "x-amz-cf-id"},
			},
			TakeoverDoc: xyz,
		},

		// ── Azure ─────────────────────────────────────────────────────────────
		{
			Name:   "Microsoft Azure",
			Status: models.StatusVulnerable,
			CNAMESuffixes: []string{
				".azurewebsites.net", ".cloudapp.net", ".cloudapp.azure.com",
				".trafficmanager.net", ".blob.core.windows.net", ".azure-api.net",
				".azurehdinsight.net", ".azurecontainer.io", ".database.windows.net",
				".azuredatalakestore.net", ".search.windows.net", ".redis.cache.windows.net",
				".servicebus.windows.net", ".visualstudio.com", ".azurefd.net",
			},
			Headers: []HeaderMatch{
				{Key: "x-ms-request-id"},
				{Key: "x-ms-version"},
			},
			BodySignals: []BodySignal{
				{Contains: "404 Web Site not found"},
			},
			ClaimCheck: nxClaim(
				".azurewebsites.net", ".cloudapp.net", ".cloudapp.azure.com",
				".trafficmanager.net", ".blob.core.windows.net", ".azure-api.net",
				".azurecontainer.io", ".azurefd.net",
			),
			TakeoverDoc: xyz,
			ClaimURL:    "https://portal.azure.com/",
		},

		// ── GitHub ────────────────────────────────────────────────────────────
		{
			Name:          "GitHub Pages",
			Status:        models.StatusEdgeCase,
			CNAMESuffixes: []string{".github.io"},
			Headers: []HeaderMatch{
				{Key: "server", Contains: "GitHub.com"},
				{Key: "x-github-request-id"},
			},
			BodySignals: []BodySignal{
				{Contains: "There isn't a GitHub Pages site here"},
			},
			ClaimCheck:  githubClaim,
			TakeoverDoc: xyz,
			ClaimURL:    "https://github.com/new",
		},

		// ── Modern hosting ────────────────────────────────────────────────────
		{
			Name:          "Heroku",
			Status:        models.StatusEdgeCase,
			CNAMESuffixes: []string{".herokuapp.com", ".herokussl.com", ".herokudns.com"},
			Headers: []HeaderMatch{
				{Key: "via", Contains: "heroku"},
				{Key: "x-heroku-error-id"},
			},
			BodySignals: []BodySignal{
				{Contains: "No such app"},
				{Contains: "herokucdn.com/error-pages/no-such-app.html"},
			},
			ClaimCheck: func(ctx context.Context, env *CheckEnv, cname string) (bool, error) {
				// Only *.herokuapp.com app names can be re-registered;
				// herokudns.com targets are random and bound to an account.
				if !strings.HasSuffix(strings.ToLower(cname), ".herokuapp.com") {
					return false, nil
				}
				return bodyClaim("no-such-app", "No such app")(ctx, env, cname)
			},
			TakeoverDoc: xyz,
			ClaimURL:    "https://dashboard.heroku.com/new-app",
		},
		{
			Name:          "Netlify",
			Status:        models.StatusEdgeCase,
			CNAMESuffixes: []string{".netlify.app", ".netlify.com"},
			Headers: []HeaderMatch{
				{Key: "server", Contains: "Netlify"},
				{Key: "x-nf-request-id"},
			},
			BodySignals: []BodySignal{{Contains: "Not Found - Request ID"}},
			ClaimCheck:  bodyClaim("Not Found - Request ID"),
			TakeoverDoc: xyz,
			ClaimURL:    "https://app.netlify.com/",
		},
		{
			Name:          "Vercel",
			Status:        models.StatusEdgeCase,
			CNAMESuffixes: []string{".vercel.app", ".now.sh"},
			Headers: []HeaderMatch{
				{Key: "server", Contains: "Vercel"},
				{Key: "x-vercel-id"},
			},
			BodySignals: []BodySignal{
				{Contains: "DEPLOYMENT_NOT_FOUND"},
				{Contains: "The deployment could not be found"},
			},
			ClaimCheck:  bodyClaim("DEPLOYMENT_NOT_FOUND"),
			TakeoverDoc: xyz,
			ClaimURL:    "https://vercel.com/new",
		},
		{
			Name:          "Render",
			Status:        models.StatusEdgeCase,
			CNAMESuffixes: []string{".onrender.com"},
			Headers:       []HeaderMatch{{Key: "x-render-origin-server"}},
			BodySignals:   []BodySignal{{Contains: "service not found", CaseInsens: true}},
			TakeoverDoc:   xyz,
		},
		{
			Name:          "Fly.io",
			Status:        models.StatusNotVulnerable,
			CNAMESuffixes: []string{".fly.dev"},
			Headers:       []HeaderMatch{{Key: "fly-request-id"}},
			TakeoverDoc:   xyz,
		},
		{
			Name:          "Digital Ocean",
			Status:        models.StatusVulnerable,
			CNAMESuffixes: []string{".ondigitalocean.app"},
			BodySignals:   []BodySignal{{Contains: "Domain uses DO name servers with no records in DO."}},
			TakeoverDoc:   xyz,
		},
		{
			Name:          "Webflow",
			Status:        models.StatusEdgeCase,
			CNAMESuffixes: []string{".webflow.io", "proxy-ssl.webflow.com", "proxy.webflow.com"},
			Headers:       []HeaderMatch{{Key: "x-wf-region"}},
			BodySignals: []BodySignal{
				{Contains: "The page you are looking for doesn't exist or has been moved."},
			},
			TakeoverDoc: xyz,
		},
		{
			Name:          "Firebase Hosting",
			Status:        models.StatusNotVulnerable,
			CNAMESuffixes: []string{".web.app", ".firebaseapp.com"},
			TakeoverDoc:   xyz,
		},
		{
			Name:          "Surge.sh",
			Status:        models.StatusVulnerable,
			CNAMESuffixes: []string{".surge.sh", "na-west1.surge.sh"},
			BodySignals:   []BodySignal{{Contains: "project not found"}},
			ClaimCheck:    bodyClaim("project not found"),
			TakeoverDoc:   xyz,
		},
		{
			Name:          "Pantheon",
			Status:        models.StatusVulnerable,
			CNAMESuffixes: []string{".pantheonsite.io"},
			BodySignals: []BodySignal{
				{Contains: "404 error unknown site!"},
				{Contains: "The gods are wise, but do not know of the site which you seek"},
			},
			TakeoverDoc: xyz,
		},
		{
			Name:          "Read the Docs",
			Status:        models.StatusVulnerable,
			CNAMESuffixes: []string{".readthedocs.io", ".readthedocs.org"},
			BodySignals: []BodySignal{
				{Contains: "The link you have followed or the URL that you entered does not exist."},
				{Contains: "Unknown Project"},
			},
			TakeoverDoc: xyz,
		},
		{
			Name:          "Bitbucket",
			Status:        models.StatusVulnerable,
			CNAMESuffixes: []string{".bitbucket.io"},
			BodySignals:   []BodySignal{{Contains: "Repository not found"}},
			ClaimCheck:    bodyClaim("Repository not found"),
			TakeoverDoc:   xyz,
		},
		{
			Name:          "Fastly",
			Status:        models.StatusNotVulnerable,
			CNAMESuffixes: []string{".global.prod.fastly.net", ".fastly.net", ".fastlylb.net"},
			Headers:       []HeaderMatch{{Key: "x-fastly-request-id"}},
			TakeoverDoc:   xyz,
		},

		// ── SaaS / CMS ────────────────────────────────────────────────────────
		{
			Name:          "Shopify",
			Status:        models.StatusEdgeCase,
			CNAMESuffixes: []string{".myshopify.com", "shops.myshopify.com"},
			Headers:       []HeaderMatch{{Key: "x-shopid"}, {Key: "x-shopify-stage"}},
			BodySignals: []BodySignal{
				{Contains: "Sorry, this shop is currently unavailable."},
			},
			TakeoverDoc: xyz,
			ClaimURL:    "https://accounts.shopify.com/store-login",
		},
		{
			Name:          "Tumblr",
			Status:        models.StatusEdgeCase,
			CNAMESuffixes: []string{"domains.tumblr.com"},
			BodySignals: []BodySignal{
				{Contains: "Whatever you were looking for doesn't currently exist at this address"},
			},
			TakeoverDoc: xyz,
		},
		{
			Name:          "Ghost",
			Status:        models.StatusVulnerable,
			CNAMESuffixes: []string{".ghost.io"},
			BodySignals: []BodySignal{
				{Contains: "Site unavailable."},
				{Contains: "Failed to resolve DNS path for this host"},
			},
			ClaimCheck:  bodyClaim("Failed to resolve DNS path for this host", "Site unavailable."),
			TakeoverDoc: xyz,
		},
		{
			Name:          "Intercom",
			Status:        models.StatusEdgeCase,
			CNAMESuffixes: []string{"custom.intercom.help", ".intercom.io"},
			BodySignals: []BodySignal{
				{Contains: "Uh oh. That page doesn't exist."},
				{Contains: "This page is reserved for artistic dogs"},
			},
			TakeoverDoc: xyz,
		},
		{
			Name:          "WordPress.com",
			Status:        models.StatusVulnerable,
			CNAMESuffixes: []string{".wordpress.com"},
			BodySignals:   []BodySignal{{Contains: "Do you want to register"}},
			TakeoverDoc:   xyz,
		},
		{
			Name:          "Agile CRM",
			Status:        models.StatusVulnerable,
			CNAMESuffixes: []string{"cname.agilecrm.com", ".agilecrm.com"},
			BodySignals:   []BodySignal{{Contains: "Sorry, this page is no longer available."}},
			TakeoverDoc:   xyz,
		},
		{
			Name:          "Cargo Collective",
			Status:        models.StatusVulnerable,
			CNAMESuffixes: []string{".cargocollective.com"},
			BodySignals:   []BodySignal{{Contains: "If you're moving your domain away from Cargo"}},
			TakeoverDoc:   xyz,
		},
		{
			Name:          "Campaign Monitor",
			Status:        models.StatusVulnerable,
			CNAMESuffixes: []string{".createsend.com"},
			BodySignals:   []BodySignal{{Contains: "Trying to access your account?"}},
			TakeoverDoc:   xyz,
		},
		{
			Name:          "Canny",
			Status:        models.StatusVulnerable,
			CNAMESuffixes: []string{"cname.canny.io", ".canny.io"},
			BodySignals: []BodySignal{
				{Contains: "Company Not Found"},
				{Contains: "There is no such company. Did you enter the right URL?"},
			},
			TakeoverDoc: xyz,
		},
		{
			Name:          "Gemfury",
			Status:        models.StatusVulnerable,
			CNAMESuffixes: []string{".furyns.com"},
			BodySignals:   []BodySignal{{Contains: "404: This page could not be found."}},
			TakeoverDoc:   xyz,
		},
		{
			Name:          "Help Juice",
			Status:        models.StatusVulnerable,
			CNAMESuffixes: []string{".helpjuice.com"},
			BodySignals:   []BodySignal{{Contains: "We could not find what you're looking for."}},
			TakeoverDoc:   xyz,
		},
		{
			Name:          "Help Scout",
			Status:        models.StatusVulnerable,
			CNAMESuffixes: []string{".helpscoutdocs.com"},
			BodySignals:   []BodySignal{{Contains: "No settings were found for this company:"}},
			TakeoverDoc:   xyz,
		},
		{
			Name:          "JetBrains YouTrack",
			Status:        models.StatusVulnerable,
			CNAMESuffixes: []string{".myjetbrains.com"},
			BodySignals:   []BodySignal{{Contains: "is not a registered InCloud YouTrack"}},
			TakeoverDoc:   xyz,
		},
		{
			Name:          "Ngrok",
			Status:        models.StatusVulnerable,
			CNAMESuffixes: []string{".ngrok.io", ".ngrok-free.app", ".ngrok.app"},
			BodySignals: []BodySignal{
				{Contains: "ngrok.io not found"},
				{Contains: "ERR_NGROK_3200"},
			},
			TakeoverDoc: xyz,
		},
		{
			Name:          "Pingdom",
			Status:        models.StatusVulnerable,
			CNAMESuffixes: []string{"stats.pingdom.com"},
			BodySignals:   []BodySignal{{Contains: "Sorry, couldn't find the status page"}},
			TakeoverDoc:   xyz,
		},
		{
			Name:          "Readme.io",
			Status:        models.StatusVulnerable,
			CNAMESuffixes: []string{".readme.io", "ssl.readmessl.com"},
			BodySignals: []BodySignal{
				{Contains: "The creators of this project are still working on making everything perfect!"},
			},
			TakeoverDoc: xyz,
		},
		{
			Name:          "SmartJobBoard",
			Status:        models.StatusVulnerable,
			CNAMESuffixes: []string{".smartjobboard.com"},
			BodySignals: []BodySignal{
				{Contains: "This job board website is either expired or its domain name is invalid."},
			},
			TakeoverDoc: xyz,
		},
		{
			Name:          "Strikingly",
			Status:        models.StatusVulnerable,
			CNAMESuffixes: []string{"s.strikinglydns.com", ".strikinglydns.com"},
			BodySignals:   []BodySignal{{Contains: "PAGE NOT FOUND."}},
			TakeoverDoc:   xyz,
		},
		{
			Name:          "SurveySparrow",
			Status:        models.StatusVulnerable,
			CNAMESuffixes: []string{".surveysparrow.com"},
			BodySignals:   []BodySignal{{Contains: "Account not found."}},
			TakeoverDoc:   xyz,
		},
		{
			Name:          "Uberflip",
			Status:        models.StatusVulnerable,
			CNAMESuffixes: []string{"read.uberflip.com", ".uberflip.com"},
			BodySignals:   []BodySignal{{Contains: "The URL you've accessed does not provide a hub."}},
			TakeoverDoc:   xyz,
		},
		{
			Name:          "UptimeRobot",
			Status:        models.StatusVulnerable,
			CNAMESuffixes: []string{"stats.uptimerobot.com"},
			BodySignals:   []BodySignal{{Contains: "page not found"}},
			TakeoverDoc:   xyz,
		},
		{
			Name:          "Worksites",
			Status:        models.StatusVulnerable,
			CNAMESuffixes: []string{".worksites.net"},
			BodySignals: []BodySignal{
				{Contains: "Hello! Sorry, but the website you&rsquo;re looking for doesn&rsquo;t exist."},
			},
			TakeoverDoc: xyz,
		},
		{
			Name:          "HatenaBlog",
			Status:        models.StatusVulnerable,
			CNAMESuffixes: []string{".hatenablog.com"},
			BodySignals:   []BodySignal{{Contains: "404 Blog is not found"}},
			TakeoverDoc:   xyz,
		},
		{
			Name:          "Discourse",
			Status:        models.StatusVulnerable,
			CNAMESuffixes: []string{".trydiscourse.com"},
			ClaimCheck:    nxClaim(".trydiscourse.com"),
			TakeoverDoc:   xyz,
		},

		// ── Not vulnerable (identified for context only) ──────────────────────
		{
			Name:          "Zendesk",
			Status:        models.StatusNotVulnerable,
			CNAMESuffixes: []string{".zendesk.com"},
			Headers:       []HeaderMatch{{Key: "x-zendesk-origin-server"}},
			TakeoverDoc:   xyz,
		},
		{
			Name:          "Freshdesk",
			Status:        models.StatusNotVulnerable,
			CNAMESuffixes: []string{".freshdesk.com"},
			TakeoverDoc:   xyz,
		},
		{
			Name:          "HubSpot",
			Status:        models.StatusNotVulnerable,
			CNAMESuffixes: []string{".hubspot.net", ".hs-sites.com", ".hubspotpagebuilder.com"},
			TakeoverDoc:   xyz,
		},
		{
			Name:          "UserVoice",
			Status:        models.StatusNotVulnerable,
			CNAMESuffixes: []string{".uservoice.com"},
			TakeoverDoc:   xyz,
		},
		{
			Name:          "Squarespace",
			Status:        models.StatusNotVulnerable,
			CNAMESuffixes: []string{".squarespace.com"},
			TakeoverDoc:   xyz,
		},
	}
}
