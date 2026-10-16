package pipeline

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/MrEx-Right/SubReaper/internal/config"
	"github.com/MrEx-Right/SubReaper/internal/models"
	"github.com/MrEx-Right/SubReaper/internal/ratelimit"
)

const maxBodyBytes = 32 * 1024 // max bytes to read from response body

// stageHTTP performs Stage 2 of the pipeline: HTTP/HTTPS probing.
//
// It probes both HTTP and HTTPS for the target domain, capturing status codes,
// headers, redirect chains, and TLS certificate information. The body is
// limited to maxBodyBytes to avoid memory issues while still extracting signals.
//
// This stage intentionally does NOT interpret the results — it only collects
// evidence for Stage 3 (fingerprinting).
func stageHTTP(ctx context.Context, domain string, chain *models.DNSChain, cfg *config.Config, limiter *ratelimit.Limiter) []*models.HTTPProbe {
	targets := []string{
		"https://" + domain,
		"http://" + domain,
	}

	// Also probe the final CNAME endpoint directly
	if chain != nil {
		if cname := chain.FinalCNAME(); cname != "" && cname != domain {
			targets = append(targets, "https://"+cname, "http://"+cname)
		}
	}

	// Probes run concurrently so that dead hosts cost one timeout, not four.
	probes := make([]*models.HTTPProbe, len(targets))
	var wg sync.WaitGroup
	for i, target := range targets {
		wg.Add(1)
		go func(i int, target string) {
			defer wg.Done()
			if err := limiter.Wait(ctx); err != nil {
				probes[i] = &models.HTTPProbe{URL: target, Error: err.Error()}
				return
			}
			probes[i] = probeURL(ctx, target, cfg.Timeout)
		}(i, target)
	}
	wg.Wait()
	return probes
}

// probeURL performs a single HTTP probe against the given URL.
func probeURL(ctx context.Context, rawURL string, timeout time.Duration) *models.HTTPProbe {
	probe := &models.HTTPProbe{
		URL:     rawURL,
		Headers: make(map[string][]string),
	}

	start := time.Now()

	// Build a client that captures TLS info and follows redirects with tracking
	var tlsSubject, tlsIssuer string
	var redirectChain []string

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // We are not validating — we are fingerprinting
		},
		DisableKeepAlives: true,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			redirectChain = append(redirectChain, req.URL.String())
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		probe.Error = err.Error()
		return probe
	}
	req.Header.Set("User-Agent", "SubReaper/2.0 (+https://github.com/MrEx-Right/SubReaper)")

	resp, err := client.Do(req)
	if err != nil {
		probe.Error = err.Error()
		probe.ResponseTime = time.Since(start)
		return probe
	}
	defer resp.Body.Close()

	probe.ResponseTime = time.Since(start)
	probe.StatusCode = resp.StatusCode
	probe.RedirectChain = redirectChain

	// Copy headers
	for k, v := range resp.Header {
		probe.Headers[k] = v
	}

	// Extract TLS certificate info
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		tlsSubject = cert.Subject.CommonName
		if len(cert.Issuer.Organization) > 0 {
			tlsIssuer = cert.Issuer.Organization[0]
		} else {
			tlsIssuer = cert.Issuer.CommonName
		}
	}
	probe.TLSSubject = tlsSubject
	probe.TLSIssuer = tlsIssuer

	// Read limited body
	limited := io.LimitReader(resp.Body, maxBodyBytes)
	body, err := io.ReadAll(limited)
	if err == nil {
		probe.Body = body
	}

	return probe
}
